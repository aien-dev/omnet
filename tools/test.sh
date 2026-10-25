#!/bin/sh
# Run every unit's test suite. Each om/<unit>/test/run.sh receives the pinned
# compiler path as $1 and exits 0 only when every vector and mutant check passes.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
omc=$("$root/tools/omc.sh")
fail=0
for t in "$root"/om/*/test/run.sh; do
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
