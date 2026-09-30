import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import verify_encrypted_application as application


@unittest.skipUnless(sys.platform == "linux", "encrypted application evaluation requires Linux")
class ApplicationCheckoutTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="continuum-checkout-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "source"
        self.source.mkdir()
        self.destination = self.directory / "copy"
        home = self.directory / "home"
        home.mkdir()
        hooks = self.directory / "empty-hooks"
        hooks.mkdir()
        self.environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        self.environment.update({
            "HOME": str(home), "XDG_CONFIG_HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Synthetic fixture", "GIT_COMMITTER_NAME": "Synthetic fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        })
        self.git_options = ["-c", "init.templateDir=", "-c", "commit.gpgSign=false",
                            "-c", "core.hooksPath=" + str(hooks)]
        for directory in ("work", "outputs"):
            (self.source / directory).mkdir()
            (self.source / directory / ".gitkeep").write_bytes(b"")
        (self.source / "source.py").write_text("# synthetic tracked source\n")
        (self.source / ".gitignore").write_text(
            "work/*\n!work/.gitkeep\noutputs/*\n!outputs/.gitkeep\n"
            "__pycache__/\n*.egg-info/\nbuild/\ndist/\n.venv/\n"
        )
        self.git("init", "--quiet")
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "Synthetic checkout fixture")
        self.commit = self.git("rev-parse", "HEAD").strip()

    def git(self, *arguments, cwd=None):
        return subprocess.check_output(
            ["git", *self.git_options, *arguments], cwd=cwd or self.source,
            env=self.environment, text=True, stderr=subprocess.STDOUT,
        )

    def copy(self, commit=None):
        # Only the checkout location is replaced; Git and copying are real.
        with patch.object(application, "ROOT", self.source):
            application.copy_checkout(self.destination, commit or self.commit, self.environment)

    def test_preserves_all_tracked_files_but_no_generated_content(self):
        generated = (
            "work/private/vault.db", "outputs/package.whl", "work/generated.txt",
            "build/generated.txt", "dist/package.tar.gz", ".venv/secret.txt",
            "__pycache__/source.pyc", "fixture.egg-info/PKG-INFO",
        )
        for name in generated:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic generated canary")
        tracked = self.git("ls-files", "-z").rstrip("\0").split("\0")
        self.copy()
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.destination).strip(), self.commit)
        self.assertEqual(self.git("status", "--porcelain", cwd=self.destination), "")
        for name in tracked:
            with self.subTest(tracked=name):
                copied = self.destination / name
                self.assertTrue(copied.is_file())
                self.assertFalse(copied.is_symlink())
                self.assertEqual(copied.read_bytes(), (self.source / name).read_bytes())
        for name in generated:
            with self.subTest(generated=name):
                self.assertFalse((self.destination / name).exists())
                self.assertEqual((self.source / name).read_bytes(), b"synthetic generated canary")

    def test_missing_and_nonregular_placeholders_fail_before_copy(self):
        outside = self.directory / "outside"
        outside.write_bytes(b"outside synthetic canary")
        for directory in ("work", "outputs"):
            placeholder = self.source / directory / ".gitkeep"
            for kind in ("missing", "symlink", "hardlink", "directory", "fifo"):
                with self.subTest(directory=directory, kind=kind):
                    placeholder.unlink()
                    if kind == "symlink":
                        placeholder.symlink_to(outside)
                    elif kind == "hardlink":
                        os.link(outside, placeholder)
                    elif kind == "directory":
                        placeholder.mkdir()
                    elif kind == "fifo":
                        os.mkfifo(placeholder)
                    try:
                        with self.assertRaisesRegex(RuntimeError, "source placeholder"):
                            self.copy()
                        self.assertFalse(self.destination.exists())
                        self.assertEqual(outside.read_bytes(), b"outside synthetic canary")
                    finally:
                        if kind == "directory":
                            placeholder.rmdir()
                        elif kind != "missing":
                            placeholder.unlink()
                        placeholder.write_bytes(b"")

    def test_symlink_placeholder_parent_fails_before_copy(self):
        for directory in ("work", "outputs"):
            parent = self.source / directory
            moved = self.directory / (directory + "-outside")
            with self.subTest(directory=directory):
                parent.rename(moved)
                parent.symlink_to(moved, target_is_directory=True)
                try:
                    with self.assertRaisesRegex(RuntimeError, "source placeholder parent"):
                        self.copy()
                    self.assertFalse(self.destination.exists())
                finally:
                    parent.unlink()
                    moved.rename(parent)

    def test_unrelated_tracked_symlink_is_not_dereferenced(self):
        outside = self.directory / "outside-directory"
        outside.mkdir()
        (outside / "private.txt").write_bytes(b"outside synthetic canary")
        (self.source / "linked").symlink_to(outside, target_is_directory=True)
        self.git("add", "linked")
        self.git("commit", "--quiet", "-m", "Synthetic tracked link fixture")
        self.commit = self.git("rev-parse", "HEAD").strip()
        self.copy()
        # The unchanged packaging guard will reject this link, not package its target.
        self.assertTrue((self.destination / "linked").is_symlink())
        self.assertEqual(os.readlink(self.destination / "linked"), str(outside))
        self.assertEqual((outside / "private.txt").read_bytes(), b"outside synthetic canary")

    def test_malformed_or_mismatched_commit_fails_before_copy(self):
        for commit in ("not-a-commit", self.commit[:8], "0" * 40):
            with self.subTest(commit=commit), self.assertRaises(RuntimeError):
                self.copy(commit)
            self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
