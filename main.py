#!/usr/bin/env python3
"""File Integrity Monitor (FIM).

Baseline SHA-256 hashes of a directory, then detect added, modified,
and deleted files on later checks.

Usage:
    python main.py init   --target <dir> [--baseline <file>] [--ignore PATTERN ...]
    python main.py check  --target <dir> [--baseline <file>] [--ignore PATTERN ...]
                          [--format text|json] [--report <file>]
    python main.py report --baseline <file> [--format text|json]

Ignore rules come from, in order:
  1. A `.fimignore` file in the target directory (one glob per line,
     `#` comments and blank lines ignored).
  2. `--ignore` CLI flags (repeatable).

A pattern matches a file if it matches its path relative to the target
directory (fnmatch, plus `**` handled by fnmatch on the full relative
path) or any parent directory name, so `__pycache__` ignores a whole
tree and `*.log` ignores log files anywhere below the target.

Unreadable files are recorded with hash None and reported as
"unreadable" rather than crashing the run. The baseline file itself
and `.fimignore` are always excluded from hashing.
"""

import argparse
import fnmatch
import hashlib
import json
import os
import sys
from pathlib import Path

DEFAULT_BASELINE = ".fim-baseline.json"
CHUNK_SIZE = 1024 * 1024


def load_ignore_patterns(target: Path, extra=()):
    """Collect ignore patterns from .fimignore plus CLI flags."""
    patterns = []
    ignore_file = target / ".fimignore"
    if ignore_file.is_file():
        try:
            for line in ignore_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
        except OSError:
            pass  # unreadable ignore file: proceed with CLI patterns only
    patterns.extend(extra)
    return patterns


def is_ignored(rel_posix: str, patterns) -> bool:
    """True if rel_posix matches a pattern, or lives under an ignored dir."""
    parts = rel_posix.split("/")
    for pattern in patterns:
        pat = pattern.strip().strip("/")
        if not pat:
            continue
        if fnmatch.fnmatch(rel_posix, pat):
            return True
        # Match any parent directory component, e.g. "__pycache__"
        # ignores "a/__pycache__/x.pyc" as well as "__pycache__/x.pyc".
        if any(fnmatch.fnmatch(part, pat) for part in parts[:-1]):
            return True
        # Bare filename patterns such as "*.log" should match at any depth.
        if "/" not in pat and fnmatch.fnmatch(parts[-1], pat):
            return True
    return False


def hash_file(path: Path):
    """SHA-256 hex digest, or None if the file cannot be read."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            while chunk := fh.read(CHUNK_SIZE):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def scan(target: Path, patterns, exclude_files=()):
    """Return {relative_posix_path: sha256_or_None} for all files."""
    target = target.resolve()
    exclude = {Path(f).name for f in exclude_files}
    results = {}
    for root, dirs, files in os.walk(target):
        root_path = Path(root)
        # Prune ignored directories so we never descend into them.
        dirs[:] = [
            d
            for d in dirs
            if not is_ignored(
                (root_path / d).relative_to(target).as_posix(), patterns
            )
        ]
        for name in files:
            if name in exclude:
                continue
            rel = (root_path / name).relative_to(target).as_posix()
            if is_ignored(rel, patterns):
                continue
            results[rel] = hash_file(root_path / name)
    return results


def load_baseline(baseline_path: Path):
    with baseline_path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise ValueError(f"baseline file is not in the expected format: {baseline_path}")
    return data


def diff(baseline_files: dict, current_files: dict):
    """Compare two {path: hash} maps. Returns a report dict."""
    added, modified, deleted, unreadable = [], [], [], []
    for path, digest in sorted(current_files.items()):
        if path not in baseline_files:
            added.append(path)
        elif digest is None or baseline_files[path] is None:
            unreadable.append(path)
        elif digest != baseline_files[path]:
            modified.append(path)
    for path in sorted(baseline_files):
        if path not in current_files:
            deleted.append(path)
    return {
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "unreadable": unreadable,
    }


def format_text(report: dict, target: str) -> str:
    lines = [f"File integrity check: {target}"]
    total = sum(len(report[k]) for k in ("added", "modified", "deleted"))
    if total == 0 and not report["unreadable"]:
        lines.append("OK — no changes detected.")
    for key, label in (
        ("added", "Added"),
        ("modified", "Modified"),
        ("deleted", "Deleted"),
        ("unreadable", "Unreadable (could not be hashed)"),
    ):
        for path in report[key]:
            lines.append(f"  {label}: {path}")
    lines.append(
        f"Summary: {len(report['added'])} added, "
        f"{len(report['modified'])} modified, "
        f"{len(report['deleted'])} deleted, "
        f"{len(report['unreadable'])} unreadable."
    )
    return "\n".join(lines) + "\n"


def cmd_init(args) -> int:
    target = Path(args.target)
    if not target.is_dir():
        print(f"error: target is not a directory: {target}", file=sys.stderr)
        return 2
    patterns = load_ignore_patterns(target, args.ignore or [])
    baseline_path = Path(args.baseline) if args.baseline else target / DEFAULT_BASELINE
    files = scan(target, patterns, exclude_files={baseline_path.name, ".fimignore"})
    payload = {"target": str(target.resolve()), "files": files}
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Baseline written: {baseline_path} ({len(files)} files)")
    return 0


def cmd_check(args) -> int:
    target = Path(args.target)
    if not target.is_dir():
        print(f"error: target is not a directory: {target}", file=sys.stderr)
        return 2
    baseline_path = Path(args.baseline) if args.baseline else target / DEFAULT_BASELINE
    if not baseline_path.is_file():
        print(
            f"error: baseline not found: {baseline_path} (run 'init' first)",
            file=sys.stderr,
        )
        return 2
    try:
        baseline = load_baseline(baseline_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read baseline: {exc}", file=sys.stderr)
        return 2
    patterns = load_ignore_patterns(target, args.ignore or [])
    current = scan(target, patterns, exclude_files={baseline_path.name, ".fimignore"})
    report = diff(baseline["files"], current)
    report["target"] = str(target.resolve())
    if args.format == "json":
        output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    else:
        output = format_text(report, str(target.resolve()))
    if args.report:
        Path(args.report).write_text(output, encoding="utf-8")
    print(output, end="")
    changed = bool(report["added"] or report["modified"] or report["deleted"])
    return 1 if changed else 0


def cmd_report(args) -> int:
    baseline_path = Path(args.baseline)
    if not baseline_path.is_file():
        print(f"error: baseline not found: {baseline_path}", file=sys.stderr)
        return 2
    try:
        baseline = load_baseline(baseline_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read baseline: {exc}", file=sys.stderr)
        return 2
    files = baseline["files"]
    if args.format == "json":
        print(json.dumps({"target": baseline.get("target"), "files": files}, indent=2, sort_keys=True))
    else:
        print(f"Baseline: {baseline_path} (target: {baseline.get('target')})")
        for path in sorted(files):
            digest = files[path] or "(unreadable)"
            print(f"  {digest}  {path}")
        print(f"Total: {len(files)} files")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="Baseline SHA-256 hashes of a directory and detect later changes.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create a baseline of a directory.")
    p_init.add_argument("--target", required=True, help="Directory to baseline.")
    p_init.add_argument("--baseline", help="Baseline JSON path (default: <target>/.fim-baseline.json).")
    p_init.add_argument("--ignore", action="append", default=[], help="Extra glob pattern to ignore (repeatable).")
    p_init.set_defaults(func=cmd_init)

    p_check = sub.add_parser("check", help="Compare a directory against its baseline.")
    p_check.add_argument("--target", required=True, help="Directory to check.")
    p_check.add_argument("--baseline", help="Baseline JSON path (default: <target>/.fim-baseline.json).")
    p_check.add_argument("--ignore", action="append", default=[], help="Extra glob pattern to ignore (repeatable).")
    p_check.add_argument("--format", choices=["text", "json"], default="text", help="Report format.")
    p_check.add_argument("--report", help="Also write the report to this file.")
    p_check.set_defaults(func=cmd_check)

    p_report = sub.add_parser("report", help="Show the stored baseline.")
    p_report.add_argument("--baseline", required=True, help="Baseline JSON path.")
    p_report.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")
    p_report.set_defaults(func=cmd_report)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
