"""Ephemeral daemon and MCP client harness. Never touches real agent profiles."""

import errno
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from continuum_memory import storage
from continuum_memory.client import DaemonClient
from continuum_memory.errors import MemoryError
from continuum_memory.security import MAX_FRAME_BYTES, canonical_json, sign_grant, write_private
from continuum_memory.storage import Store, load_capability, paths


def open_fixture_connection(data_dir: Path, *, writable: bool = False, read_only: bool = False):
    """Inspect a keyed fixture without implicitly upgrading its schema."""
    files = paths(data_dir)
    connection = storage._connect(
        files["db"],
        storage._read_storage_key(files["storage_key"]),
        apply_hardening=writable,
        read_only=read_only,
    )
    connection.row_factory = None
    return connection


MCP_STARTUP_TIMEOUT = 5.0


def private_test_home(temporary_name: str) -> Path:
    """Create a new Windows ACL-protected child; never chmod a broad temp root."""
    root = Path(temporary_name)
    if os.name == "nt":
        from continuum_memory.security import create_private_directory
        root = root / "vault"
        create_private_directory(root)
    return root


class McpFixtureClient:
    def __init__(self, data_dir: Path, capability_file: Path, client_name: str):
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join([str(root / "src"), str(root)])
        environment["PYTHONPYCACHEPREFIX"] = str(root / "work" / "pycache")
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "continuum_memory.mcp",
                "--data-dir",
                str(data_dir),
                "--capability-file",
                str(capability_file),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=environment,
        )
        self.client_name = client_name
        self.counter = 0
        self._wait_ready()

    def _wait_ready(self) -> None:
        # A spawned process is not yet a ready client. Finish its private-path
        # checks before the demo starts mutating the shared synthetic vault.
        # Discovery is stateless, so legacy initialization still works later.
        outcome: queue.Queue = queue.Queue(maxsize=1)

        def discover() -> None:
            try:
                response = self.request("server/discover")
                result = response.get("result") if isinstance(response, dict) else None
                info = result.get("serverInfo") if isinstance(result, dict) else None
                ready = (
                    isinstance(response, dict)
                    and response.get("jsonrpc") == "2.0"
                    and type(response.get("id")) is int
                    and response["id"] == 1
                    and "error" not in response
                    and isinstance(result, dict)
                    and result.get("protocolVersion") == "2026-07-28"
                    and isinstance(info, dict)
                    and info.get("name") == "continuum-memory"
                )
            except Exception:
                ready = False
            outcome.put(ready)

        worker = threading.Thread(target=discover, name="continuum-mcp-fixture-ready", daemon=True)
        worker.start()
        try:
            try:
                ready = outcome.get(timeout=MCP_STARTUP_TIMEOUT)
            except queue.Empty:
                ready = False
            if not ready:
                raise RuntimeError("MCP fixture did not become ready") from None
        except BaseException:
            # Reap first: a stalled pipe reader cannot be joined while its child
            # is still alive. Never retry or relax a failed permission check.
            try:
                if self.process.poll() is None:
                    self.process.kill()
                self.process.wait(timeout=2)
            finally:
                worker.join(timeout=2)
                self.close()
            raise
        worker.join(timeout=2)

    def _meta(self) -> Dict[str, Any]:
        return {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": self.client_name, "version": "fixture-1"},
        }

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self.counter += 1
        payload_params = dict(params or {})
        payload_params.setdefault("_meta", self._meta())
        request = {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": payload_params}
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        self.process.stdin.write(canonical_json(request) + "\n")
        self.process.stdin.flush()
        return self._read_response()

    def _read_response(self) -> Dict[str, Any]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline(MAX_FRAME_BYTES + 1)
        if not line:
            raise RuntimeError("MCP fixture exited without a response")
        if not line.endswith("\n") or len(line.encode("utf-8")) > MAX_FRAME_BYTES:
            raise RuntimeError("MCP fixture response exceeds its frame boundary")
        return json.loads(line)

    def request_legacy(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self.counter += 1
        request = {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params or {}}
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        self.process.stdin.write(canonical_json(request) + "\n")
        self.process.stdin.flush()
        return self._read_response()

    def discover(self) -> Dict[str, Any]:
        return self.request("server/discover")["result"]

    def tools(self) -> List[Dict[str, Any]]:
        return self.request("tools/list")["result"]["tools"]

    def call_raw(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        response = self.call_raw(name, arguments)
        if "error" in response:
            raise RuntimeError(response["error"])
        result = response["result"]
        if result.get("isError"):
            error = result["structuredContent"]["error"]
            raise MemoryError(error["code"], error["message"], error.get("details"))
        return result["structuredContent"]

    def close(self) -> None:
        try:
            try:
                if self.process.stdin:
                    try:
                        self.process.stdin.close()
                    except BrokenPipeError:
                        pass
                    except OSError as error:
                        # Windows may report EINVAL while flushing a dead pipe.
                        # Other errors still propagate after bounded reaping.
                        if os.name != "nt" or error.errno != errno.EINVAL or self.process.poll() is None:
                            raise
            finally:
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=2)
        finally:
            if self.process.stdout:
                self.process.stdout.close()
            if self.process.stderr:
                self.process.stderr.close()


class EphemeralHarness:
    def __init__(self, daemon_module: str = "fixtures.prototype_daemon"):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-memory-test-")
        self.clients: List[McpFixtureClient] = []
        self.daemon = None
        try:
            self._start(daemon_module)
        except BaseException:
            self.close()
            raise

    def _start(self, daemon_module: str) -> None:
        self.data_dir = private_test_home(self.temporary.name)
        self.marker = self.data_dir / ".continuum-test-vault"
        project_specs = [
            {"name": "alpha", "path_hint": "/fixture/alpha", "providers": ["codex", "claude"]},
            {"name": "beta", "path_hint": "/fixture/beta", "providers": ["codex", "claude"]},
        ]
        self.bootstrap = Store.bootstrap(self.data_dir, project_specs)
        write_private(self.marker, b"ephemeral fixture only\n")
        self.projects = {entry["name"]: entry for entry in self.bootstrap["projects"]}
        self.control = DaemonClient(self.data_dir, paths(self.data_dir)["control"])
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(root / "src")
        environment["PYTHONPYCACHEPREFIX"] = str(root / "work" / "pycache")
        self.daemon = subprocess.Popen(
            [sys.executable, "-m", daemon_module, "--data-dir", str(self.data_dir)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=environment,
        )
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.daemon.poll() is not None:
                stderr = self.daemon.stderr.read().decode("utf-8") if self.daemon.stderr else ""
                raise RuntimeError("daemon failed: %s" % stderr)
            # Named pipes have no socket-file readiness marker. A real response
            # proves the transport, capability authentication and store are ready.
            try:
                self.control.call("status", {"project": self.projects["alpha"]["id"]})
                return
            except MemoryError:
                pass
            time.sleep(0.02)
        raise RuntimeError("daemon did not become ready")

    def mcp(self, project: str, provider: str) -> McpFixtureClient:
        capability = Path(self.projects[project]["capabilities"][provider])
        client = McpFixtureClient(self.data_dir, capability, "%s-fixture" % provider)
        self.clients.append(client)
        return client

    def approve(self, params: Dict[str, Any]) -> Dict[str, Any]:
        # The fake broker is intentionally limited to an ephemeral marked test vault.
        temp_root = Path(tempfile.gettempdir()).resolve()
        resolved = self.data_dir.resolve()
        if temp_root not in resolved.parents or not self.marker.exists():
            raise RuntimeError("test broker refuses non-ephemeral vault")
        challenge = self.control.call("admin_preview", params)
        control = load_capability(paths(self.data_dir)["control"])
        grant = sign_grant(
            control["token"].encode("ascii"),
            challenge["nonce"],
            challenge["operation"],
            challenge["preview_digest"],
        )
        result = self.control.call(
            "admin_apply",
            {
                "nonce": challenge["nonce"],
                "preview_digest": challenge["preview_digest"],
                "grant": grant,
                "preview": challenge["preview"],
            },
        )
        return {"challenge": challenge, "result": result, "grant": grant}

    def replay(self, approval: Dict[str, Any]) -> Dict[str, Any]:
        challenge = approval["challenge"]
        return self.control.call(
            "admin_apply",
            {
                "nonce": challenge["nonce"],
                "preview_digest": challenge["preview_digest"],
                "grant": approval["grant"],
                "preview": challenge["preview"],
            },
        )

    def close(self) -> None:
        for client in self.clients:
            client.close()
        self.clients = []
        if self.daemon is not None and self.daemon.poll() is None:
            self.daemon.terminate()
            try:
                self.daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
                self.daemon.wait(timeout=2)
        if self.daemon is not None and self.daemon.stderr:
            self.daemon.stderr.close()
        self.temporary.cleanup()

    def __enter__(self) -> "EphemeralHarness":
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()
