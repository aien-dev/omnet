#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# CBOR test suite. Usage: sh om/cbor/test/run.sh OMC
# Builds blake2s.om + cbor.om + test/driver.om with the pinned omc into build/test/cbor/, then checks:
#   rfc8949-appA  RFC 8949 Appendix A: accept/reject code, and canonical re-encoding of accepted rows
#   tka-structs   1200 tka AUM / NodeKeySignature / State encodings: decode, re-encode byte for byte,
#                 BLAKE2s-256 = tka AUM.Hash, key-1 lookup
#   hostile       hostile corpus: error code = fxamacker Wellformed, per-class duties (see README)
#   fuzz          2000 mutations: error code = fxamacker Wellformed
#   utf8          2000 text strings: cbrutf8 = Go utf8.Valid
# A driver trap (exit >= 100) or a short output fails the check. Then every mutant must be detected:
# its driver runs must all complete normally and at least one case must differ.
# With CBOR_GO set to a Go toolchain >= 1.26.5, the oracle vectors are regenerated and must equal the
# committed ones (else that step prints NOT_RUN). Exit 0 only when everything passes.
set -eu
omc=${1:?usage: run.sh OMC}
here=$(cd "$(dirname "$0")" && pwd)
unit=$(dirname "$here")
root=$(cd "$unit/../.." && pwd)
out="$root/build/test/cbor"
vec="$here/vectors"
rm -rf "$out"
mkdir -p "$out"
fail=0

build() { # build CBOR_SOURCE OUTPUT
	cat "$root/om/blake2s/blake2s.om" "$1" "$here/driver.om" > "$2.om"
	"$omc" < "$2.om" > "$2" 2> "$2.err" || {
		echo "cbor: omc failed on $1: $(cat "$2.err")"
		return 1
	}
	chmod +x "$2"
}

# inputs: one hex column of each vector file, comments dropped
awk '!/^#/ { print $2 }' "$vec/rfc8949-appA.txt" > "$out/appA.in"
awk '!/^#/ { print $2 }' "$vec/tka-structs.txt" > "$out/tka.in"
awk '!/^#/ { print $6 }' "$vec/hostile.txt" > "$out/hostile.in"
awk '!/^#/ { print $4 }' "$vec/fuzz.txt" > "$out/fuzz.in"
awk '!/^#/ { print $2 }' "$vec/utf8.txt" > "$out/utf8.in"

# judge NAME VECTORFILE GOT: compare the driver output GOT with the vector file, line by line.
# Prints "PASS/FAIL count" lines. Returns 0 when every case matches, 1 when the output is complete
# and at least one case differs, 2 when the output does not have one line per case.
judge() {
	awk -v name="$1" '
		FNR == NR { if ($0 !~ /^#/) v[++nv] = $0; next }
		{ g[++ng] = $0 }
		function want(wf) { return (wf == 0) ? "ok" : "e" wf }
		END {
			bad = 0
			if (ng != nv) { printf "cbor: %s FAIL (%d output lines for %d cases)\n", name, ng, nv; exit 2 }
			for (i = 1; i <= nv; i++) {
				split(v[i], a, " "); split(g[i], b, " "); ok = 1
				if (name == "rfc8949-appA") {
					ok = (b[1] == want(a[1])) && (a[1] != 0 || b[6] == a[2])
				} else if (name == "tka-structs") {
					ok = b[1] == "ok" && b[3] == 0 && b[4] == 1 && b[5] == a[4] && b[6] == a[2] && b[7] == a[3]
					n[a[1]]++; if (ok) p[a[1]]++
				} else if (name == "hostile") {
					c = a[1]; ok = b[1] == want(a[3])
					if (c == "D") ok = ok && b[3] == 1
					if (c == "U") ok = ok && b[4] == 0
					if (c == "R") ok = ok && b[6] == a[5]
					n[c]++; if (ok) p[c]++
				} else if (name == "fuzz") {
					ok = b[1] == want(a[1])
					if (a[2] == 1 || a[3] == 1) ok = ok && b[1] == "ok"
				} else if (name == "utf8") {
					ok = b[1] == "ok" && b[4] == a[1]
				}
				if (!ok) { bad++; if (bad <= 3) printf "cbor: %s MISMATCH case %d: want [%s] got [%s]\n", name, i, substr(v[i], 1, 160), substr(g[i], 1, 160) }
			}
			detail = ""
			for (k in n) detail = detail sprintf(" %s %d/%d", k, p[k], n[k])
			printf "cbor: %s %d/%d %s%s\n", name, nv - bad, nv, bad ? "FAIL" : "PASS", detail
			exit bad != 0
		}
	' "$2" "$3"
}

# suite BINARY TAG: run every vector file through BINARY. Sets srun=1 when any run was abnormal
# (driver exit status not 0: trap 100+N, signal 128+N, launch failure 126/127, malformed-line 2; or
# output without one line per case) and smis=1 when a complete run had a case that differs.
# Returns 0 only when every run was normal and every case matched.
suite() {
	bin=$1
	tag=$2
	srun=0
	smis=0
	for c in "rfc8949-appA appA" "tka-structs tka" "hostile hostile" "fuzz fuzz" "utf8 utf8"; do
		name=${c% *}
		f=${c#* }
		st=0
		"$bin" < "$out/$f.in" > "$out/$f.$tag.got" 2> /dev/null || st=$?
		if [ "$st" -ne 0 ]; then
			echo "cbor: $name driver exit $st ABNORMAL FAIL"
			srun=1
		fi
		jr=0
		judge "$name" "$vec/$name.txt" "$out/$f.$tag.got" || jr=$?
		if [ "$jr" -eq 2 ]; then
			srun=1
		elif [ "$jr" -ne 0 ] && [ "$st" -eq 0 ]; then
			smis=1
		fi
	done
	[ "$srun" -eq 0 ] && [ "$smis" -eq 0 ]
}

drv="$out/driver"
build "$unit/cbor.om" "$drv"
echo "cbor: omc sha256 $(sha256sum "$omc" | cut -d' ' -f1)"
echo "cbor: cbor.om sha256 $(sha256sum "$unit/cbor.om" | cut -d' ' -f1)"
echo "cbor: driver sha256 $(sha256sum "$drv" | cut -d' ' -f1)"
suite "$drv" main || fail=1

# oracle reproducibility (needs Go >= 1.26.5 and the module proxy or a warm module cache)
if [ -n "${CBOR_GO:-}" ]; then
	mkdir -p "$out/regen"
	if sh "$here/gen/regen.sh" "$CBOR_GO" "$out/regen" > "$out/regen.log" 2>&1; then
		same=1
		for f in tka-structs hostile fuzz utf8; do
			grep -v '^#' "$vec/$f.txt" > "$out/regen/$f.want"
			grep -v '^#' "$out/regen/$f.txt" | cmp -s - "$out/regen/$f.want" || { same=0; echo "cbor: regen $f differs FAIL"; }
		done
		[ "$same" -eq 1 ] && echo "cbor: oracle regeneration identical PASS" || fail=1
	else
		echo "cbor: oracle regeneration FAIL: $(tail -n 3 "$out/regen.log")"
		fail=1
	fi
else
	echo "cbor: NOTE CBOR_GO not set, oracle regeneration NOT_RUN (committed vectors checked above)"
fi

# expectation mutant: one hash digit of the first tka structure flipped must be reported
awk 'BEGIN { done = 0 } !done && !/^#/ { c = substr($3, 1, 1); $3 = ((c == "0") ? "1" : "0") substr($3, 2); done = 1 } { print }' \
	"$vec/tka-structs.txt" > "$out/mut-expect.txt"
if judge tka-structs "$out/mut-expect.txt" "$out/tka.main.got" > /dev/null; then
	echo "cbor: mutant expected-hash NOT detected FAIL"
	fail=1
else
	echo "cbor: mutant expected-hash detected PASS"
fi

# source mutants: each replaces every line equal to FROM (at least one) and must fail the suite
mutant() { # mutant NAME FROM TO
	m="$out/mut-$1"
	awk -v from="$2" -v to="$3" '$0 == from { $0 = to; hit++ } { print } END { exit hit < 1 }' \
		"$unit/cbor.om" > "$m.cbor.om" || { echo "cbor: mutant $1 did not apply FAIL"; fail=1; return 0; }
	build "$m.cbor.om" "$m" || { fail=1; return 0; }
	suite "$m" "$1" > "$m.log" 2>&1 || true
	# detected only when every driver run completed normally and some case differs
	if [ "$srun" -ne 0 ]; then
		echo "cbor: mutant $1 run ABNORMAL (trap, signal or short output), not a detection FAIL"
		fail=1
	elif [ "$smis" -eq 0 ]; then
		echo "cbor: mutant $1 NOT detected FAIL"
		fail=1
	else
		echo "cbor: mutant $1 detected PASS ($(grep -c 'FAIL' "$m.log") failing checks)"
	fi
}
mutant depth-17 "if ge dep 16" "if ge dep 17"
mutant array-4097 "if and eq m 4 gt v 4096" "if and eq m 4 gt v 4097"
mutant map-1023 "if and eq m 5 gt v 1024" "if and eq m 5 gt v 1023"
mutant tags-allowed "if eq m 6" "if eq m 8"
mutant extra-bytes "if ne p n" "if lt n p"
mutant simple-lt32 "if and eq m 7 and eq a 24 lt v 32" "if and eq m 7 and eq a 24 lt v 31"
mutant len-overflow "if gt v sub n q" "if gt v n"
mutant shortest-head "if lt v 24" "if lt v 23"
mutant sort-reversed "ret gt x y" "ret lt x y"
mutant sort-off "if and eq cbrmaj t i 5 gt cbrval t i 1" "if and eq cbrmaj t i 5 gt cbrval t i 1024"
mutant int64-keys "ret not cbrval t i" "ret cbrval t i"
mutant utf8-surrogates "ret 159" "ret 191"

exit "$fail"
