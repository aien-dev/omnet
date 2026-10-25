#!/bin/sh
# Run library and executable suites with the pinned compiler path as $1.
# Each suite exits 0 only when its behavior checks pass.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
omc=$("$root/tools/omc.sh")
fail=0
for t in "$root"/om/*/test/run.sh "$root"/cmd/*/test/run.sh; do
	[ -f "$t" ] || continue
	unit=$(basename "$(dirname "$(dirname "$t")")")
	if sh "$t" "$omc"; then
		echo "PASS $unit"
	else
		echo "FAIL $unit"
		fail=1
	fi
done
exit "$fail"
