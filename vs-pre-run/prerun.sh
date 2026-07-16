#!/usr/bin/env bash
# prerun.sh — trim release/ to the KEEP most recent semver directories.
#
# Invoked by vs-pre-run/Makefile (make prerun / end of make all) so the repo
# does not accumulate hundreds of committed binary release folders.
set -euo pipefail

KEEP="${KEEP_RELEASES:-10}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE_DIR="${ROOT}/release"

if [ ! -d "$RELEASE_DIR" ]; then
	echo "prerun: release directory not found, skipping."
	exit 0
fi

# Collect version directories only (ignore AGENTS.md and other non-version entries).
versions=()
while IFS= read -r name; do
	[ -n "$name" ] || continue
	if [[ "$name" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
		versions+=("$name")
	fi
done < <(ls -1 "$RELEASE_DIR" 2>/dev/null | sort -V)

total=${#versions[@]}
if [ "$total" -le "$KEEP" ]; then
	echo "prerun: keeping all $total release version(s) (limit $KEEP)."
	exit 0
fi

remove_count=$((total - KEEP))
echo "prerun: trimming release/ from $total to $KEEP version(s) (removing $remove_count)..."

for ((i = 0; i < remove_count; i++)); do
	ver="${versions[$i]}"
	target="$RELEASE_DIR/$ver"
	if [ ! -d "$target" ]; then
		continue
	fi
	echo "  removing release/$ver"
	rm -rf "$target"
done

remaining=$((total - remove_count))
echo "prerun: done — $remaining release version(s) retained."
