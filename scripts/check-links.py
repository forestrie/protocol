#!/usr/bin/env python3
"""Fail on any relative link that does not resolve, and on any reference to a private source."""
import os, re, sys, subprocess

FORBIDDEN = [
    "github.com/forestrie/devdocs",
    "github.com/forestrie/forestrie-agents",
    "github.com/forestrie/thinker",
    "github.com/forestrie/product",
    "linear.app",
]
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

files = subprocess.check_output(["git", "ls-files"], text=True).split()
bad = 0
for f in files:
    if f.startswith("vectors/golden/") and not f.endswith(".json"):
        continue
    if f.startswith("scripts/"):
        continue
    try:
        text = open(f, encoding="utf-8").read()
    except UnicodeDecodeError:
        continue
    for needle in FORBIDDEN:
        for i, line in enumerate(text.splitlines(), 1):
            if needle in line:
                print(f"{f}:{i}: forbidden reference {needle}")
                bad += 1
    if not f.endswith(".md"):
        continue
    for m in LINK.finditer(text):
        target = m.group(1)
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        path = target.split("#", 1)[0]
        if not path:
            continue
        resolved = os.path.normpath(os.path.join(os.path.dirname(f), path))
        if not os.path.exists(resolved):
            line = text[: m.start()].count("\n") + 1
            print(f"{f}:{line}: relative link does not resolve: {target}")
            bad += 1
print(f"{'FAIL' if bad else 'OK'}: {bad} problem(s) in {len(files)} tracked files")
sys.exit(1 if bad else 0)
