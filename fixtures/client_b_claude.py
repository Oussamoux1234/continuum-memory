#!/usr/bin/env python3
"""Deterministic Client B fixture: recall one Claude-labeled project decision."""

import argparse
import json
from pathlib import Path

from fixtures.harness import McpFixtureClient


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--capability-file", type=Path, required=True)
    args = parser.parse_args()
    client = McpFixtureClient(args.data_dir, args.capability_file, "claude-fixture-b")
    try:
        search = client.call("memory_search", {"query": "SQLite", "limit": 5})
        records = []
        if search["cards"]:
            records = client.call(
                "memory_get",
                {"recall_id": search["recall_id"], "ids": [search["cards"][0]["version_id"]]},
            )["records"]
        print(json.dumps({"search": search, "records": records}, sort_keys=True))
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
