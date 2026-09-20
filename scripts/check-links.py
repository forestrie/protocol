#!/usr/bin/env python3
"""Fail on any relative link that does not resolve, on any reference to a private
source, and on any line that carries a ticket id, a plan id or a lifecycle
status header: the specification says what is true, not when or under which
ticket.

    check-links.py             check every tracked file
    check-links.py --self-test prove the patterns catch what they are for
"""
import os, re, sys, subprocess

FORBIDDEN = [
    "github.com/forestrie/devdocs",
    "github.com/forestrie/forestrie-agents",
    "github.com/forestrie/thinker",
    "github.com/forestrie/product",
    "linear.app",
]
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

# Lines that state when or under which ticket, rather than what. The frozen
# vector manifests keep the comment their exporter wrote (see
# vectors/README.md) and their bytes are pinned, and the records under
# decisions/ speak in their own historical voice (README: "historical records
# in their own voice"), so both are exempt from every pattern below; the
# specification, rules, glossary, README and vector prose are not.
LINE_PATTERNS = [
    (re.compile(r"\bFOR-\d+\b"), "ticket id"),
    (re.compile(r"\bplan-\d{4}\b"), "plan id"),
    (re.compile(r"^\*\*Status:\*\* LIVE\b"), "lifecycle status header"),
    (re.compile(r"^\*\*Date:\*\* \d{4}-\d{2}-\d{2}"), "date header"),
]


def is_pinned_data(path):
    """Every non-Markdown file under vectors/ is frozen bytes pinned by SHA256SUMS."""
    return path.startswith("vectors/") and not path.endswith((".md", "SHA256SUMS"))


PINNED_MANIFESTS = ("vectors/golden/manifest.json", "vectors/golden/burial/manifest.json")


def line_problems(path, text):
    for i, line in enumerate(text.splitlines(), 1):
        for needle in FORBIDDEN:
            if needle in line:
                yield i, f"forbidden reference {needle}"
        if is_pinned_data(path) or path.startswith("decisions/"):
            continue
        for pattern, what in LINE_PATTERNS:
            if pattern.search(line):
                yield i, what


def self_test():
    sample = "\n".join([
        "**Status:** LIVE",
        "**Date:** 2026-08-30",
        "see FOR-123 and plan-2609 for context",
        "https://github.com/forestrie/devdocs/blob/main/x.md",
    ])
    found = sorted(what for _, what in line_problems("spec/sample.md", sample))
    want = sorted(["lifecycle status header", "date header", "ticket id", "plan id", "forbidden reference github.com/forestrie/devdocs"])
    if found != want:
        print(f"self-test FAIL: found {found}, want {want}")
        return 1
    exempt = list(line_problems("decisions/sample.md", "**Status:** LIVE\n**Date:** 2026-08-30\nFOR-1 plan-2609"))
    if exempt:
        print(f"self-test FAIL: decisions/ must be exempt, got {exempt}")
        return 1
    for pinned in (PINNED_MANIFESTS[0], "vectors/fixtures/sample.json"):
        exempt = list(line_problems(pinned, '{"comment": "FOR-289 golden vectors"}'))
        if exempt:
            print(f"self-test FAIL: pinned data must be exempt, got {exempt}")
            return 1
    if not list(line_problems("vectors/sample.md", "FOR-1")):
        print("self-test FAIL: vector prose must be checked")
        return 1
    print("self-test OK")
    return 0


if "--self-test" in sys.argv[1:]:
    sys.exit(self_test())

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
    for i, what in line_problems(f, text):
        print(f"{f}:{i}: {what}")
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
