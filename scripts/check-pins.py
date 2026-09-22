#!/usr/bin/env python3
"""Every data file under vectors/ must be pinned in vectors/SHA256SUMS, and nothing else may be.

`sha256sum -c` only checks the files that are listed; a new or renamed file
under vectors/ would otherwise ship unpinned. Markdown under vectors/ is prose
and is deliberately not pinned, so that a changed SHA256SUMS always means
changed vector bytes.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMS = "vectors/SHA256SUMS"

tracked = subprocess.check_output(["git", "ls-files", "vectors"], cwd=ROOT, text=True).split()
expected = {f for f in tracked if f != SUMS and not f.endswith(".md")}
pinned = set()
with open(os.path.join(ROOT, SUMS), encoding="utf-8") as fh:
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        digest, _, path = line.partition("  ")
        if len(digest) != 64 or not path:
            print(f"{SUMS}: malformed line: {line!r}")
            sys.exit(1)
        pinned.add(path)

bad = 0
for f in sorted(expected - pinned):
    print(f"{f}: tracked under vectors/ but not pinned in {SUMS}")
    bad += 1
for f in sorted(pinned - expected):
    print(f"{f}: pinned in {SUMS} but not a tracked data file under vectors/")
    bad += 1
print(f"{'FAIL' if bad else 'OK'}: {len(pinned)} pinned, {bad} problem(s)")
sys.exit(1 if bad else 0)
