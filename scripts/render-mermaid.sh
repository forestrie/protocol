#!/usr/bin/env bash
# Render every ```mermaid fence in tracked Markdown with mermaid-cli; fail on the first that does not render.
set -euo pipefail
tmp="$(mktemp -d)"
n=0
for f in $(git ls-files '*.md'); do
  awk -v out="$tmp" -v src="$f" '
    /^```mermaid[[:space:]]*$/ { inblk=1; n++; file=out "/" src "-" n ".mmd"; gsub("/", "_", file); file=out "/" file; next }
    /^```[[:space:]]*$/ && inblk { inblk=0; close(file); next }
    inblk { print > file }
  ' "$f"
done
for m in "$tmp"/*.mmd; do
  [ -e "$m" ] || continue
  n=$((n+1))
  npx --yes @mermaid-js/mermaid-cli@11 -p "$(dirname "$0")/puppeteer-config.json" -i "$m" -o "$m.svg" -q
done
echo "OK: $n mermaid block(s) rendered"
