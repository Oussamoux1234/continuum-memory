"""Synthetic CLI/dead-process fault seams, restricted to ephemeral test vaults.

Never imported by the product. Approval is deliberately NOT human-presence
evidence; daemon, storage, grants and local transport otherwise remain real.
"""

import argparse
import json
import os
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from continuum_memory import cli, client, daemon, recovery_journal
from continuum_memory.daemon import MemoryServer, RequestHandler, serve
from continuum_memory.security import (
    create_private_directory, ensure_private_regular, read_private, replace_private, sign_grant, write_private,
)
from continuum_memory.storage import load_capability, paths
from fixtures.prototype_daemon import prototype_kernel


def check_fixture(home):
    home = home.resolve()
    if Path(tempfile.gettempdir()).resolve() not in home.parents:
        raise RuntimeError("CLI crash fixture requires a temporary vault")
    ensure_private_regular(home / ".continuum-test-vault")


def barrier(ready_fd, release_fd):
    if ready_fd < 0 or release_fd < 0:
        raise RuntimeError("Crash fixture barrier was not configured")
    os.write(ready_fd, b"R")
    if os.read(release_fd, 1) != b"G":
        raise RuntimeError("Crash fixture barrier was not released")


def run_cli(home, point, ready_fd, release_fd, argv):
    check_fixture(home)
    token = load_capability(paths(home)["control"])["token"]

    class SyntheticBroker:
        def authorize(self, challenge):
            return sign_grant(token.encode("ascii"), challenge["nonce"],
                              challenge["operation"], challenge["preview_digest"])

    original_persist = recovery_journal.persist_locator
    original_print = cli._print
    original_socket = socket.socket

    def persist(*args, **kwargs):
        if point == "before_journal":
            os._exit(73)
        result = original_persist(*args, **kwargs)
        if point == "after_journal":
            os._exit(73)
        return result

    def output(value, compact):
        if point in {"before_print", "in_flight"} and value.get("commit", {}).get("status") == "committed":
            os._exit(73)
        return original_print(value, compact)

    class FaultSocket(original_socket):
        applying = False

        def sendall(self, payload, *args, **kwargs):
            self.applying = json.loads(payload)["method"] == "admin_apply"
            if not self.applying:
                return super().sendall(payload, *args, **kwargs)
            if point == "before_send":
                os._exit(73)
            if point in {"partial_send", "in_flight"}:
                if not payload.endswith(b"\n"):
                    raise AssertionError("Fixture must hold the actual frame terminator")
                super().sendall(payload[:-1], *args, **kwargs)
                if point == "partial_send":
                    os._exit(73)
                barrier(ready_fd, release_fd)
                return super().sendall(payload[-1:], *args, **kwargs)
            return super().sendall(payload, *args, **kwargs)

        def recv(self, *args, **kwargs):
            if self.applying and point == "before_reply":
                barrier(ready_fd, release_fd)
                os._exit(73)
            return super().recv(*args, **kwargs)

    with patch.object(cli, "broker_for_challenge", return_value=SyntheticBroker()), \
            patch.object(cli, "persist_locator", side_effect=persist), \
            patch.object(cli, "_print", side_effect=output), \
            patch.object(client, "CLIENT_TIMEOUT", 30 if point == "in_flight" else client.CLIENT_TIMEOUT):
        # Named-pipe happy-path tests do not touch the Unix-specific fault seam.
        if os.name == "nt":
            return cli.main(argv)
        with patch("continuum_memory.client.socket.socket", FaultSocket):
            return cli.main(argv)


def run_daemon(home, point, ready_fd, release_fd):
    check_fixture(home)
    original = MemoryServer._respond
    original_handle = RequestHandler.handle
    held = False
    trace_dir = home / ".cli-recovery-fixture"
    if not trace_dir.exists():
        create_private_directory(trace_dir)
    trace = trace_dir / "methods"
    if not trace.exists():
        write_private(trace, b"")

    def handle(handler, raw):
        # Only fixture-generated complete frames reach this test-only trace.
        # It demonstrates recovery never even attempts a mutation or approval.
        method = json.loads(raw)["method"]
        if method not in {"status", "admin_preview", "admin_apply", "admin_recover", "audit_verify"}:
            raise AssertionError("Unexpected method in CLI recovery fixture")
        replace_private(trace, read_private(trace) + method.encode("ascii") + b"\n")
        return original_handle(handler, raw)

    def respond(server, connection, output):
        nonlocal held
        value = json.loads(output)
        if (point == "before_reply" and not held
                and value.get("result", {}).get("commit", {}).get("status") == "committed"):
            held = True
            # Real RequestHandler/Kernel/Store have returned a committed result;
            # no response has yet been scheduled or written to the socket.
            barrier(ready_fd, release_fd)
        return original(server, connection, output)

    # The deliberate incomplete-frame rendezvous must not turn a slow CI Python
    # startup into a transport-timeout test. Production deadlines stay unchanged.
    with patch.object(MemoryServer, "_respond", respond), patch.object(RequestHandler, "handle", handle), \
            patch.object(daemon, "READ_TIMEOUT", 30 if point == "in_flight" else daemon.READ_TIMEOUT):
        serve(home, kernel_factory=prototype_kernel)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", nargs="?", choices=["cli", "daemon"], default="daemon")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--point", default="none")
    parser.add_argument("--ready-fd", type=int, default=-1)
    parser.add_argument("--release-fd", type=int, default=-1)
    args, remainder = parser.parse_known_args()
    if args.mode == "daemon":
        return run_daemon(args.data_dir, args.point, args.ready_fd, args.release_fd)
    return run_cli(args.data_dir, args.point, args.ready_fd, args.release_fd,
                   ["--data-dir", str(args.data_dir), "--json"] + remainder)


if __name__ == "__main__":
    raise SystemExit(main())
