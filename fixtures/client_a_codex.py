#!/usr/bin/env python3
"""Deterministic Client A fixture: submit one Codex-labeled proposal."""

import argparse
import json
from pathlib import Path

from fixtures.harness import McpFixtureClient


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--capability-file", type=Path, required=True)
    args = parser.parse_args()
    client = McpFixtureClient(args.data_dir, args.capability_file, "codex-fixture-a")
    try:
        result = client.call(
            "memory_propose",
            {
                "subject": "database decision",
                "claim": "This project uses SQLite because the local slice must stay offline.",
                "evidence": "Milestone 1 architecture decision",
                "source_handle": "fixture:client-a",
                "classification": "internal",
                "retention": "forever",
                "disclosure": ["codex", "claude"],
                "idempotency_key": "fixture-client-a-0001",
            },
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
