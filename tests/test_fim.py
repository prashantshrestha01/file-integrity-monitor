"""Tests for the file integrity monitor.

All fixtures live in tempfile.TemporaryDirectory() — no real user
files are ever hashed, modified, or deleted by these tests.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "main.py", *args],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        check=False,
    )


class TestBaselineAndDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name) / "watched"
        self.target.mkdir()
        (self.target / "a.txt").write_text("hello\n")
        (self.target / "b.txt").write_text("world\n")
        self.baseline = Path(self.tmp.name) / "baseline.json"

    def _init(self, extra_args=()):
        result = run_cli(
            "init", "--target", str(self.target),
            "--baseline", str(self.baseline), *extra_args,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def _check(self, extra_args=()):
        return run_cli(
            "check", "--target", str(self.target),
            "--baseline", str(self.baseline), *extra_args,
        )

    def test_baseline_creation(self):
        self._init()
        data = json.loads(self.baseline.read_text())
        self.assertEqual(set(data["files"]), {"a.txt", "b.txt"})
        # SHA-256 digests are 64 hex chars.
        for digest in data["files"].values():
            self.assertEqual(len(digest), 64)
        # A clean check exits 0 and reports no changes.
        result = self._check()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("no changes detected", result.stdout)

    def test_modified_file_detection(self):
        self._init()
        (self.target / "a.txt").write_text("CHANGED\n")
        result = self._check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("Modified: a.txt", result.stdout)
        self.assertNotIn("Modified: b.txt", result.stdout)

    def test_added_and_deleted_detection(self):
        self._init()
        (self.target / "c.txt").write_text("brand new\n")
        (self.target / "b.txt").unlink()
        result = self._check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("Added: c.txt", result.stdout)
        self.assertIn("Deleted: b.txt", result.stdout)

    def test_json_output(self):
        self._init()
        (self.target / "a.txt").write_text("CHANGED\n")
        result = self._check(["--format", "json"])
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["modified"], ["a.txt"])
        self.assertEqual(report["added"], [])
        self.assertEqual(report["deleted"], [])

    def test_ignore_rules_from_fimignore_file(self):
        (self.target / ".fimignore").write_text("# comment\n*.log\n__pycache__\n")
        (self.target / "debug.log").write_text("noise\n")
        cache = self.target / "__pycache__"
        cache.mkdir()
        (cache / "mod.pyc").write_bytes(b"\x00\x01")
        self._init()
        data = json.loads(self.baseline.read_text())
        self.assertNotIn("debug.log", data["files"])
        self.assertNotIn("__pycache__/mod.pyc", data["files"])
        self.assertIn("a.txt", data["files"])
        # Changing an ignored file must not show up on check.
        (self.target / "debug.log").write_text("different noise\n")
        result = self._check()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_ignore_rules_from_cli_flag(self):
        self._init(["--ignore", "b.txt"])
        data = json.loads(self.baseline.read_text())
        self.assertNotIn("b.txt", data["files"])
        (self.target / "b.txt").write_text("changed, but ignored\n")
        result = self._check(["--ignore", "b.txt"])
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_report_subcommand(self):
        self._init()
        result = run_cli("report", "--baseline", str(self.baseline))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("a.txt", result.stdout)
        self.assertIn("Total: 2 files", result.stdout)

    def test_missing_baseline_is_an_error(self):
        result = self._check()
        self.assertEqual(result.returncode, 2)
        self.assertIn("baseline not found", result.stderr)

    def test_unreadable_file_handled_gracefully(self):
        # A path that is a broken symlink cannot be read, but the scan
        # must not crash: it is recorded as unreadable.
        broken = self.target / "broken.txt"
        broken.symlink_to(self.target / "does-not-exist.txt")
        files = main.scan(self.target, [], exclude_files={".fimignore"})
        self.assertIsNone(files["broken.txt"])

    def test_help_exits_cleanly(self):
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("init", result.stdout)


if __name__ == "__main__":
    unittest.main()
