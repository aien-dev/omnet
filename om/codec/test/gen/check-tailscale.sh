#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# One-time cross-check of gen/oracle's transcription of tailscale.com v1.102.0 tka.AUMHash and
# key.NodePublic text methods against the real package. Not run by run.sh: it needs network access
# for the tailscale.com module and a Go toolchain >= 1.26.5 (that module's minimum), while
# gen/oracle is built with go1.26.0.
# Usage: sh om/codec/test/gen/check-tailscale.sh [SEED...]   (default seeds 1 2 3)
# Environment: GO (default go). Exit 0 only when both referees agree on every case.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
out="$root/build/test/codec/tscheck"
go=${GO:-go}
mkdir -p "$out"
(cd "$here/oracle" && GOTOOLCHAIN=go1.26.0 "$go" build -o "$out/oracle" .)
(cd "$here/tsoracle" && GOTOOLCHAIN=local "$go" build -o "$out/tsoracle" .)
echo "codec: oracle $(GOTOOLCHAIN=go1.26.0 "$go" version)"
echo "codec: tsoracle $(GOTOOLCHAIN=local "$go" version)"
fail=0
check() { # check NAME CASEFILE
	grep -E '^(aume|aumd|nkye|nkyd) ' "$2" > "$out/$1.in" || true
	"$out/oracle" < "$out/$1.in" > "$out/$1.oracle"
	"$out/tsoracle" < "$out/$1.in" > "$out/$1.ts"
	n=$(wc -l < "$out/$1.in" | tr -d ' ')
	if cmp -s "$out/$1.oracle" "$out/$1.ts"; then
		echo "codec: tailscale cross-check $1 $n/$n PASS"
	else
		echo "codec: tailscale cross-check $1 FAIL ($(cmp "$out/$1.oracle" "$out/$1.ts" 2>&1 || true))"
		fail=1
	fi
}
"$out/oracle" corpus | grep -v '^#' > "$out/corpus.cases"
check corpus "$out/corpus.cases"
[ $# -gt 0 ] || set -- 1 2 3
for s in "$@"; do
	"$out/oracle" rand "$s" > "$out/rand-$s.cases"
	check "rand-$s" "$out/rand-$s.cases"
done
exit "$fail"
