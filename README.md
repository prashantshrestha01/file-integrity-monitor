# File Integrity Monitor

A small command-line tool that watches a directory for unexpected changes.
It takes a baseline of SHA-256 hashes, then on later runs reports which
files were added, modified, or deleted. Think of it as a tripwire for a
config folder, a web root, or any directory where silent changes matter.

Standard library only — no dependencies to install, no services to run.

## How it works

1. `init` walks the target directory, hashes every file with SHA-256,
   and writes the results to a JSON baseline.
2. `check` hashes the directory again and diffs it against the baseline.
3. `report` prints the stored baseline so you can inspect what was recorded.

Exit codes from `check`: `0` = no changes, `1` = changes detected,
`2` = usage/baseline error. That makes it easy to wire into a cron job or
a script that alerts only when something actually moved.

## Usage

```bash
# See every command
python main.py --help

# 1. Create a baseline of a directory
python main.py init --target /path/to/watch

# 2. Check for changes (default baseline: <target>/.fim-baseline.json)
python main.py check --target /path/to/watch

# 3. Inspect the stored baseline
python main.py report --baseline /path/to/watch/.fim-baseline.json
```

Example output from a check with changes:

```
File integrity check: /path/to/watch
  Added: new-script.sh
  Modified: config.yaml
  Deleted: old-notes.txt
Summary: 1 added, 1 modified, 1 deleted, 0 unreadable.
```

### JSON output

```bash
python main.py check --target /path/to/watch --format json --report report.json
```

`--report` also writes the text report to a file, so you can keep a log
of each run alongside the console output.

### Ignore rules

Ignore patterns come from two places, combined:

- **`.fimignore`** — a file in the target directory, one glob per line.
  Blank lines and `#` comments are skipped:

  ```
  # Logs and caches change constantly; don't trip on them
  *.log
  __pycache__
  ```

- **`--ignore` flags** — repeatable, for one-off exclusions:

  ```bash
  python main.py init --target /path/to/watch --ignore "*.tmp" --ignore "cache"
  ```

A pattern matches a file's path relative to the target, any parent
directory name (so `__pycache__` ignores the whole tree), or a bare
filename at any depth (so `*.log` catches nested logs). The baseline
file itself and `.fimignore` are always excluded from hashing.

### Edge cases handled

- **Unreadable files** are recorded with no hash and listed as
  "Unreadable" instead of crashing the run — a permissions problem
  shouldn't hide every other change.
- **Missing baseline** on `check` is a clean error (`run 'init' first`),
  not a traceback.
- **Empty directories** are fine: they simply contribute no entries.

## Running the tests

```bash
python -m unittest discover -s tests -v
```

The suite covers baseline creation, modified-file detection,
added/deleted detection, JSON output, ignore rules from both
`.fimignore` and CLI flags, the `report` subcommand, missing-baseline
handling, unreadable files, and `--help`. Every test uses temporary
directories only — nothing in your real home directory is ever hashed
or touched.

## What I learned building this

- **Hashing is the easy part; matching is the fiddly part.** SHA-256 in
  a streaming loop is a few lines, but ignore rules need care: a pattern
  like `*.log` should match at any depth, and a directory name should
  prune the whole subtree, not just files directly inside it.
- **Exit codes are the interface.** A monitoring tool that only prints
  pretty text is hard to automate; returning 0/1/2 turns `check` into
  something a scheduler can act on without parsing output.
- **Fail soft on unreadable files, fail loud on a missing baseline.**
  Those are different kinds of problems: one file you can't read
  shouldn't abort the scan, but checking against a baseline that
  doesn't exist is a configuration mistake worth stopping for.
- **Keep the baseline format boring.** Plain JSON with relative paths
  and hex digests means you can inspect, diff, or edit it with any
  tool, years from now, without this program.

## Requirements

Python 3.8+ (uses the walrus operator in the hashing loop). No
third-party packages — see `requirements.txt`.

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/prashant-me/)*
