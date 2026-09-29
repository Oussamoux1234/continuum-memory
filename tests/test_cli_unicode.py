"""Real redirected CLI output must not depend on the Windows ANSI codepage."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from continuum_memory import cli


ROOT = Path(__file__).resolve().parents[1]
PROJECT = "Décision — 東京 — مرحبا — 🧠"


class CliUnicodeTest(unittest.TestCase):
    def test_redirected_init_preserves_unicode_in_compact_and_pretty_json(self):
        environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"),
                           PYTHONIOENCODING="cp1252", PYTHONUTF8="0")
        with tempfile.TemporaryDirectory(prefix="continuum-cli-unicode-") as temporary:
            for compact in (False, True):
                with self.subTest(compact=compact):
                    vault = Path(temporary) / ("compact" if compact else "pretty")
                    command = [sys.executable, "-m", "continuum_memory.cli", "--data-dir", str(vault)]
                    if compact:
                        command.append("--json")
                    command.extend(["init", "--project-name", PROJECT, "--project-path", temporary])
                    result = subprocess.run(command, env=environment, capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, b"")
                    output = result.stdout.decode("utf-8")
                    self.assertIn(PROJECT, output)
                    self.assertEqual(json.loads(output)["projects"][0]["name"], PROJECT)
                    self.assertEqual(len(output.splitlines()) == 1, compact)

    def test_entrypoint_preserves_replaced_text_stream_compatibility(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            cli.main(["--version"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertTrue(output.getvalue().startswith("continuum "))
