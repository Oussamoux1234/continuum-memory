"""Ephemeral daemon and MCP client harness. Never touches real agent profiles."""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from continuum_memory.client import DaemonClient
from continuum_memory.errors import MemoryError
from continuum_memory.security import canonical_json, sign_grant
from continuum_memory.storage import Store, load_capability, paths


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
            bufsize=1,
            env=environment,
        )
        self.client_name = client_name
        self.counter = 0

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
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError("MCP fixture exited without a response: %s" % stderr)
        return json.loads(line)

    def request_legacy(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self.counter += 1
        request = {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params or {}}
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        self.process.stdin.write(canonical_json(request) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("MCP legacy fixture exited without a response")
        return json.loads(line)

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
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=2)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()


class EphemeralHarness:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-memory-test-")
        self.data_dir = Path(self.temporary.name)
        self.marker = self.data_dir / ".continuum-test-vault"
        project_specs = [
            {"name": "alpha", "path_hint": "/fixture/alpha", "providers": ["codex", "claude"]},
            {"name": "beta", "path_hint": "/fixture/beta", "providers": ["codex", "claude"]},
        ]
        self.bootstrap = Store.bootstrap(self.data_dir, project_specs)
        self.marker.write_text("ephemeral fixture only\n", encoding="utf-8")
        os.chmod(str(self.marker), 0o600)
        self.projects = {entry["name"]: entry for entry in self.bootstrap["projects"]}
        self.control = DaemonClient(self.data_dir, paths(self.data_dir)["control"])
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(root / "src")
        environment["PYTHONPYCACHEPREFIX"] = str(root / "work" / "pycache")
        self.daemon = subprocess.Popen(
            [sys.executable, "-m", "continuum_memory.daemon", "--data-dir", str(self.data_dir)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=environment,
        )
        self._wait_ready()
        self.clients: List[McpFixtureClient] = []

    def _wait_ready(self) -> None:
        socket_path = paths(self.data_dir)["socket"]
        deadline = time.time() + 5
        while time.time() < deadline:
            if self.daemon.poll() is not None:
                stderr = self.daemon.stderr.read().decode("utf-8") if self.daemon.stderr else ""
                raise RuntimeError("daemon failed: %s" % stderr)
            if socket_path.exists():
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
        if self.daemon.poll() is None:
            self.daemon.terminate()
            try:
                self.daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
                self.daemon.wait(timeout=2)
        if self.daemon.stderr:
            self.daemon.stderr.close()
        self.temporary.cleanup()

    def __enter__(self) -> "EphemeralHarness":
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()
