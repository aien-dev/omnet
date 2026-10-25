#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
OMC=${1:-$("$ROOT/tools/omc.sh")}
GO=${GO:-go}
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM
if [ "${REGEN:-0}" = 1 ]; then
    (cd "$ROOT/om/tkasig/test" && GOTOOLCHAIN=local "$GO" run -mod=readonly oracle.go) > "$BUILD/vectors.jsonl"
    cp "$BUILD/vectors.jsonl" "$ROOT/om/tkasig/test/vectors.jsonl"
fi
python3 "$ROOT/om/tkasig/test/check.py" "$OMC" "$BUILD"
