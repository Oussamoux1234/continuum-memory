#!/usr/bin/env python3
"""Opt-in, non-mutating real-polkit approval smoke test."""

import argparse
import json
import os
import sys
import time

from continuum_memory.approval import (
    LINUX_APPROVAL_BOUNDARY,
    approval_payload,
    linux_public_key,
    verify_payload,
)
from continuum_memory.broker import LinuxPolkitApprovalBroker
from continuum_memory.errors import MemoryError
from continuum_memory.security import canonical_json, digest_json, random_id


def main(argv=None):
    parser = argparse.ArgumentParser(description="Exercise a real Linux polkit approval without changing memory")
    parser.add_argument("--vault-id", required=True)
    args = parser.parse_args(argv)
    try:
        if not sys.platform.startswith("linux"):
            raise MemoryError("unsupported_platform", "The real polkit smoke test requires Linux.")
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise MemoryError("interactive_required", "The real polkit smoke test requires a terminal.")
        caller_uid = os.getuid()
        public_key = linux_public_key(caller_uid)
        if public_key is None:
            raise MemoryError("approval_broker_unavailable", "The Linux approval key is not provisioned.")
        preview = {
            "operation": "remember",
            "project_id": "prj_polkit_smoke_only",
            "subject": "non-mutating polkit smoke",
        }
        challenge = {
            "approval_boundary": LINUX_APPROVAL_BOUNDARY,
            "expires_at": int(time.time()) + 120,
            "nonce": random_id("gnt"),
            "operation": "remember",
            "preview": preview,
            "preview_digest": digest_json(preview),
            "vault_id": args.vault_id,
        }
        grant = LinuxPolkitApprovalBroker().authorize(challenge)
        payload = approval_payload(
            args.vault_id,
            caller_uid,
            challenge["nonce"],
            challenge["operation"],
            challenge["preview_digest"],
            challenge["expires_at"],
        )
        if not verify_payload(public_key, payload, grant):
            raise MemoryError("approval_invalid", "The real polkit approval signature did not verify.")
        print(canonical_json({"approval_boundary": LINUX_APPROVAL_BOUNDARY, "status": "passed"}))
        return 0
    except MemoryError as error:
        print(canonical_json({"error": error.as_dict()}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
