#!/usr/bin/env python3
"""One-command supported local verification suite."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional


ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ)
ENV["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
ENV["PYTHONPYCACHEPREFIX"] = str(ROOT / "work" / "pycache")
ENV["PIP_NO_INDEX"] = "1"
ENV["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"


def run(command: List[str], environment: Optional[Dict[str, str]] = None) -> None:
    print("+ %s" % " ".join(command), flush=True)
    subprocess.run(command, cwd=str(ROOT), env=ENV if environment is None else environment, check=True)


def schema_check() -> None:
    for path in sorted((ROOT / "schemas").glob("*.json")):
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise RuntimeError("schema version missing: %s" % path)
        print("schema ok: %s" % path.relative_to(ROOT))


def whitespace_check() -> None:
    suffixes = {".py", ".md", ".toml", ".cfg", ".yml", ".json"}
    skipped = {".git", ".venv", "work", "outputs", "build", "dist", "__pycache__"}
    for directory, directories, filenames in os.walk(str(ROOT)):
        directories[:] = [
            item for item in directories if item not in skipped and not item.endswith(".egg-info")
        ]
        for filename in filenames:
            path = Path(directory) / filename
            if path.suffix not in suffixes:
                continue
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), 1):
                if line.endswith(" ") or line.endswith("\t"):
                    raise RuntimeError("trailing whitespace: %s:%d" % (path.relative_to(ROOT), number))


def packaging_smoke() -> None:
    with tempfile.TemporaryDirectory(prefix="continuum-package-", dir=str(ROOT / "work")) as temp:
        artifacts = Path(temp) / "dist"
        artifacts.mkdir()
        run(
            [
                sys.executable,
                "setup.py",
                "--quiet",
                "sdist",
                "--dist-dir",
                str(artifacts),
            ]
        )
        archives = sorted(artifacts.glob("continuum-memory-*.tar.gz"))
        if len(archives) != 1:
            raise RuntimeError("expected exactly one source distribution, found %d" % len(archives))
        environment = str(Path(temp) / "venv")
        run([sys.executable, "-m", "venv", environment])
        python = str(Path(environment) / "bin" / "python")
        package_environment = dict(ENV)
        package_environment.pop("PYTHONPATH", None)
        run(
            [python, "-m", "pip", "install", "--no-cache-dir", "--no-deps", str(archives[0])],
            package_environment,
        )
        run([str(Path(environment) / "bin" / "continuum"), "--version"], package_environment)
        run([str(Path(environment) / "bin" / "memoryd"), "--help"], package_environment)
        run([str(Path(environment) / "bin" / "continuum-mcp"), "--help"], package_environment)


def main() -> int:
    schema_check()
    whitespace_check()
    run([sys.executable, "-m", "compileall", "-q", "src", "fixtures", "tests", "scripts"])
    run([sys.executable, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests", "-v"])
    run([sys.executable, "-m", "fixtures.demo"])
    packaging_smoke()
    run(["git", "diff", "--check"])
    print("verification: PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
