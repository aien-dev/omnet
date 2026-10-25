#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# BLAKE2s test suite. Usage: sh om/blake2s/test/run.sh OMC
# Builds lib + driver with the pinned omc into build/test/blake2s/, runs the RFC 7693 Appendix B and
# Appendix E vectors, the BLAKE2 KAT file, the boundary vectors and (when python3 is present) a
# hashlib differential corpus; then proves the harness discriminates with three mutants.
# Exit 0 only when every vector matches and every mutant is detected.
# B2S_SEED sets the differential seed (default 7693).
set -eu
omc=${1:?usage: run.sh OMC}
here=$(cd "$(dirname "$0")" && pwd)
unit=$(dirname "$here")
root=$(cd "$unit/../.." && pwd)
out="$root/build/test/blake2s"
vec="$here/vectors"
seed=${B2S_SEED:-7693}
mkdir -p "$out"
fail=0

build() { # build LIBRARY OUTPUT
	cat "$1" "$here/driver.om" | "$omc" > "$2" 2> "$2.err" || {
		echo "blake2s: omc failed on $1: $(cat "$2.err")"
		return 1
	}
	chmod +x "$2"
}

# check NAME INPUT EXPECTED: run the driver on INPUT, compare with EXPECTED byte for byte
check() {
	n=$(wc -l < "$3" | tr -d ' ')
	if "$drv" < "$2" > "$out/$1.got" && cmp -s "$out/$1.got" "$3"; then
		echo "blake2s: $1 $n/$n PASS"
	else
		echo "blake2s: $1 FAIL ($(cmp "$out/$1.got" "$3" 2>&1 || true))"
		fail=1
	fi
}

drv="$out/driver"
build "$unit/blake2s.om" "$drv"
echo "blake2s: omc sha256 $(sha256sum "$omc" | cut -d' ' -f1)"
echo "blake2s: driver sha256 $(sha256sum "$drv" | cut -d' ' -f1)"

# RFC 7693 Appendix B case lines and Appendix E grand hash
awk '$1 == "case" { print $2, $3, $4 > in_; print $5 > out_ }' \
	in_="$out/rfc.in" out_="$out/rfc.out" "$vec/rfc7693.txt"
check rfc7693-appB "$out/rfc.in" "$out/rfc.out"
want=$(awk '$1 == "selftest" { print $2 }' "$vec/rfc7693.txt")
if got=$("$drv" selftest) && [ "$got" = "$want" ]; then
	echo "blake2s: rfc7693-appE 1/1 PASS ($got)"
else
	echo "blake2s: rfc7693-appE FAIL (got ${got:-none})"
	fail=1
fi

# BLAKE2 KAT: blocks of in:/key:/hash: lines, tab separated, empty in: means the empty message
awk -F'\t' '
	$1 == "in:" { m = ($2 == "") ? "-" : $2 }
	$1 == "key:" { k = ($2 == "") ? "-" : $2 }
	$1 == "hash:" { print length($2) / 2, k, m > in_; print $2 > out_ }
' in_="$out/kat.in" out_="$out/kat.out" "$vec/blake2s-kat.txt"
[ "$(wc -l < "$out/kat.out")" -eq 256 ] || { echo "blake2s: kat parse FAIL"; fail=1; }
check kat "$out/kat.in" "$out/kat.out"

# boundary vectors: OUTN KN N DIGEST, key byte i = i, message byte i = i mod 251
awk '
	function hex(n, mod,   s, i) {
		if (n == 0) return "-"
		s = ""
		for (i = 0; i < n; i++) s = s sprintf("%02x", i % mod)
		return s
	}
	{ print $1, hex($2, 256), hex($3, 251) > in_; print $4 > out_ }
' in_="$out/boundary.in" out_="$out/boundary.out" "$vec/boundary.txt"
check boundary "$out/boundary.in" "$out/boundary.out"

# differential corpus against python3 hashlib.blake2s
if command -v python3 > /dev/null 2>&1; then
	python3 "$here/oracle.py" diff "$seed" "$out" > /dev/null
	echo "blake2s: differential seed $seed"
	check differential "$out/diff.in" "$out/diff.out"
else
	echo "blake2s: NOTE python3 not found, differential corpus NOT_RUN"
fi

# Mutant rules: a mutant counts as detected only when every run of the binary under test completed
# normally (exit 0; for "selftest" also exit 1, its documented mismatch status; never a trap exit
# 100+N, a signal or a launch failure) with complete output (one line per case, each of the
# expected length), and at least one result differs from the expected one. Output goes to files,
# never through a pipe, so no exit status is lost.

# complete EXPECTED GOT: GOT has as many newline-ended lines as EXPECTED, each of the same length
complete() {
	[ "$(wc -l < "$1")" -eq "$(wc -l < "$2")" ] || return 1
	[ -z "$(tail -c 1 "$2")" ] || return 1
	awk 'NR == FNR { l[FNR] = length($0); next } length($0) != l[FNR] { bad = 1 } END { exit bad }' \
		"$1" "$2"
}

# mutant 1: one flipped expected digit must be reported as a mismatch
awk 'NR == 1 { c = substr($0, 1, 1); $0 = ((c == "0") ? "1" : "0") substr($0, 2) } { print }' \
	"$out/kat.out" > "$out/mut-expect.out"
rc=0
"$drv" < "$out/kat.in" > "$out/mut-expect.got" || rc=$?
if [ "$rc" -ne 0 ] || ! complete "$out/mut-expect.out" "$out/mut-expect.got"; then
	echo "blake2s: mutant expected-digit run did not complete (exit $rc) FAIL"
	fail=1
elif cmp -s "$out/mut-expect.got" "$out/mut-expect.out"; then
	echo "blake2s: mutant expected-digit NOT detected FAIL"
	fail=1
else
	echo "blake2s: mutant expected-digit detected PASS"
fi

# source mutants: each must build, run to completion on the RFC case lines and the Appendix E
# self-test, and disagree with at least one of them
echo "$want" > "$out/self.out"
mutant() { # mutant NAME FROM TO
	m="$out/mut-$1"
	awk -v from="$2" -v to="$3" '$0 == from { $0 = to; hit++ } { print } END { exit hit != 1 }' \
		"$unit/blake2s.om" > "$m.om" || { echo "blake2s: mutant $1 did not apply FAIL"; fail=1; return 0; }
	build "$m.om" "$m" || { fail=1; return 0; }
	rc1=0
	"$m" < "$out/rfc.in" > "$m.rfc" || rc1=$?
	rc2=0
	"$m" selftest > "$m.self" || rc2=$?
	if [ "$rc1" -ne 0 ] || ! complete "$out/rfc.out" "$m.rfc" ||
		{ [ "$rc2" -ne 0 ] && [ "$rc2" -ne 1 ]; } || ! complete "$out/self.out" "$m.self"; then
		echo "blake2s: mutant $1 did not complete (exit $rc1, selftest exit $rc2) FAIL"
		fail=1
	elif cmp -s "$m.rfc" "$out/rfc.out" && [ "$rc2" -eq 0 ] && cmp -s "$m.self" "$out/self.out"; then
		echo "blake2s: mutant $1 NOT detected FAIL"
		fail=1
	else
		echo "blake2s: mutant $1 detected PASS"
	fi
}
mutant iv0 "put w 40 1779033703" "put w 40 1779033702"
mutant final-flag "b2scomp w 1" "b2scomp w 0"

exit "$fail"
