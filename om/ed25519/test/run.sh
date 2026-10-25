#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test suite for om/ed25519. Usage: sh om/ed25519/test/run.sh PATH_TO_PINNED_OMC
# Builds sha512.om + ed25519.om + test/driver.om into build/test/ed25519/, runs every static vector
# file in both modes, two library mutants and one expectation mutant (each must fail), the python
# differential corpus when python3 with pynacl and cryptography is present, and one timing series.
# Exit 0 only when every check passes.
# Environment: ED_DIFF_COUNT (default 2000 keypairs), ED_DIFF_SEED (default 1),
# ED_BENCH_N (default 1000 repeats of RFC 8032 TEST 1 per mode).
set -eu
omc=${1:?usage: run.sh OMC}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="$root/build/test/ed25519"
rm -rf "$out"
mkdir -p "$out"
fail=0

build() { # build SRC_ED25519 OUT_BINARY
	cat "$root/om/sha512/sha512.om" "$1" "$here/driver.om" > "$2.unit.om"
	if ! "$omc" < "$2.unit.om" > "$2" 2> "$2.err"; then
		echo "FAIL build $2: $(cat "$2.err")"
		return 1
	fi
	chmod +x "$2"
}

# run BINARY FILE LABEL: the driver must exit 0 with no mismatch
run() {
	if "$1" < "$2" > "$out/$3.log" 2>&1; then
		echo "PASS $3: $(tail -n 1 "$out/$3.log")"
	else
		echo "FAIL $3 (exit $?):"
		cat "$out/$3.log"
		fail=1
	fi
}

# mutant BINARY FILE LABEL: the driver must finish normally and report a mismatch: exit status
# exactly 1, at least one MISMATCH line, and its summary line. Any other outcome (0, 65 bad
# input, 100+N trap, a signal) fails the run, so a mutant that crashes is not counted as detected.
mutant() {
	rc=0
	"$1" < "$2" > "$out/$3.log" 2>&1 || rc=$?
	nm=$(grep -c '^MISMATCH ' "$out/$3.log" || true)
	if [ "$rc" -eq 1 ] && [ "$nm" -gt 0 ] && grep -q '^cases .* mismatches [1-9]' "$out/$3.log"; then
		echo "PASS $3 detected: $nm mismatches, $(tail -n 1 "$out/$3.log")"
	else
		echo "FAIL $3: exit $rc, $nm MISMATCH lines (need exit 1 and at least one): $(tail -n 1 "$out/$3.log")"
		fail=1
	fi
}

build "$root/om/ed25519/ed25519.om" "$out/driver"
echo "omc $(sha256sum "$omc" | cut -d' ' -f1)"
echo "ed25519.om $(sha256sum "$root/om/ed25519/ed25519.om" | cut -d' ' -f1)"
echo "sha512.om $(sha256sum "$root/om/sha512/sha512.om" | cut -d' ' -f1)"
echo "driver $(sha256sum "$out/driver" | cut -d' ' -f1)"

for v in rfc8032 zip215 wycheproof edge; do
	run "$out/driver" "$here/vectors/$v.txt" "$v"
done

# expectation mutant: the first expected-valid RFC line flipped to expected-invalid in both modes
awk 'BEGIN { done = 0 } !done && /^1 1 / { sub(/^1 1 /, "0 0 "); done = 1 } { print }' \
	"$here/vectors/rfc8032.txt" > "$out/mut-expect.txt"
mutant "$out/driver" "$out/mut-expect.txt" mutant-expectation

# library mutant 1: one limb of the constant 2d changed (point addition breaks)
sed 's/^put w 48 61785$/put w 48 61786/' "$root/om/ed25519/ed25519.om" > "$out/mut-d2.om"
if cmp -s "$root/om/ed25519/ed25519.om" "$out/mut-d2.om"; then
	echo "FAIL mutant-d2: sed did not change the source"
	fail=1
elif build "$out/mut-d2.om" "$out/mut-d2"; then
	mutant "$out/mut-d2" "$here/vectors/rfc8032.txt" mutant-d2-rfc8032
else
	fail=1
fi

# library mutant 2: the cofactor multiplication of consensus mode removed
sed '/^edpadd w edq edrr$/,/^ret edpid w edq$/{/^edpdbl w edq$/d;}' \
	"$root/om/ed25519/ed25519.om" > "$out/mut-cofactor.om"
if cmp -s "$root/om/ed25519/ed25519.om" "$out/mut-cofactor.om"; then
	echo "FAIL mutant-cofactor: sed did not change the source"
	fail=1
elif build "$out/mut-cofactor.om" "$out/mut-cofactor"; then
	mutant "$out/mut-cofactor" "$here/vectors/zip215.txt" mutant-cofactor-zip215
else
	fail=1
fi

# differential corpus (python test oracle; skipped when unavailable)
if command -v python3 > /dev/null 2>&1 &&
	python3 -c 'import nacl.signing, cryptography.hazmat.primitives.asymmetric.ed25519' 2> /dev/null; then
	python3 "$here/gen/diff.py" "$out/diff" "${ED_DIFF_COUNT:-2000}" "${ED_DIFF_SEED:-1}"
	for f in "$out"/diff/diff-*.txt; do
		run "$out/driver" "$f" "$(basename "$f" .txt)"
	done
else
	echo "NOTE differential corpus skipped: python3 with pynacl and cryptography not found"
fi

# timing: RFC 8032 TEST 1 (empty message), ED_BENCH_N verifies per mode
n=${ED_BENCH_N:-1000}
grep '^1 1 ' "$here/vectors/rfc8032.txt" | head -n 1 > "$out/t1.txt"
sed 's/^1 1 /1 - /' "$out/t1.txt" > "$out/bench-strict.txt"
sed 's/^1 1 /- 1 /' "$out/t1.txt" > "$out/bench-consensus.txt"
for m in strict consensus; do
	if "$out/driver" "$n" < "$out/bench-$m.txt" > "$out/bench-$m.log" 2>&1; then
		ns=$(awk '{ print $8 }' "$out/bench-$m.log")
		echo "TIME $m: $n verifies, $ns ns total, $((ns / n)) ns per verify"
	else
		echo "FAIL bench-$m"
		cat "$out/bench-$m.log"
		fail=1
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "ed25519: FAIL"
	exit 1
fi
echo "ed25519: all checks passed"
