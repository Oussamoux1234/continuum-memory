#!/usr/bin/env python3
"""Record non-sensitive native CI facts; do not infer architecture from a label."""

import argparse
import json
import os
import platform
import sqlite3
import subprocess
import sys


def environment_record():
    if sys.platform != "darwin":
        raise RuntimeError("native macOS is required")
    version = subprocess.check_output(["/usr/bin/sw_vers", "-productVersion"], text=True, timeout=10).strip()
    return {
        "macos_version": version, "architecture": platform.machine(),
        "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
        "runner_image": os.environ.get("ImageOS", "local-unrecorded"),
        "runner_image_version": os.environ.get("ImageVersion", "local-unrecorded"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-runner", choices=("macos-14", "macos-15"))
    args = parser.parse_args()
    record = environment_record()
    if args.expected_runner:
        if record["macos_version"].split(".")[0] != args.expected_runner.split("-")[1]:
            raise RuntimeError("observed macOS major does not match declared runner")
        if record["architecture"] != "arm64":
            raise RuntimeError("this acceptance matrix requires native arm64")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
