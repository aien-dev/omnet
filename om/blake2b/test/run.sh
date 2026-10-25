#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# BLAKE2b test suite. Usage: sh om/blake2b/test/run.sh OMC
# Builds lib + driver with the pinned omc into build/test/blake2b/, runs the RFC 7693 Appendix A and
# Appendix E vectors, the BLAKE2 KAT file, the boundary vectors and (when python3 is present) a
# hashlib differential corpus; then proves the harness discriminates with five mutants.
# Exit 0 only when every vector matches and every mutant is detected.
# B2B_SEED sets the differential seed (default 7693).
set -eu
omc=${1:?usage: run.sh OMC}
here=$(cd "$(dirname "$0")" && pwd)
unit=$(dirname "$here")
root=$(cd "$unit/../.." && pwd)
out="$root/build/test/blake2b"
vec="$here/vectors"
seed=${B2B_SEED:-7693}
mkdir -p "$out"
fail=0

build() { # build LIBRARY OUTPUT
	cat "$1" "$here/driver.om" | "$omc" > "$2" 2> "$2.err" || {
		echo "blake2b: omc failed on $1: $(cat "$2.err")"
		return 1
	}
	chmod +x "$2"
}

# check NAME INPUT EXPECTED: run the driver on INPUT, compare with EXPECTED byte for byte
check() {
	n=$(wc -l < "$3" | tr -d ' ')
	if "$drv" < "$2" > "$out/$1.got" && cmp -s "$out/$1.got" "$3"; then
		echo "blake2b: $1 $n/$n PASS"
	else
		echo "blake2b: $1 FAIL ($(cmp "$out/$1.got" "$3" 2>&1 || true))"
		fail=1
	fi
}

drv="$out/driver"
build "$unit/blake2b.om" "$drv"
echo "blake2b: omc sha256 $(sha256sum "$omc" | cut -d' ' -f1)"
echo "blake2b: driver sha256 $(sha256sum "$drv" | cut -d' ' -f1)"

# RFC 7693 Appendix A case lines and Appendix E grand hash
awk '$1 == "case" { print $2, $3, $4 > in_; print $5 > out_ }' \
	in_="$out/rfc.in" out_="$out/rfc.out" "$vec/rfc7693.txt"
check rfc7693-appA "$out/rfc.in" "$out/rfc.out"
want=$(awk '$1 == "selftest" { print $2 }' "$vec/rfc7693.txt")
if got=$("$drv" selftest) && [ "$got" = "$want" ]; then
	echo "blake2b: rfc7693-appE 1/1 PASS ($got)"
else
	echo "blake2b: rfc7693-appE FAIL (got ${got:-none})"
	fail=1
fi

# BLAKE2 KAT: blocks of in:/key:/hash: lines, tab separated, empty in: means the empty message
awk -F'\t' '
	$1 == "in:" { m = ($2 == "") ? "-" : $2 }
	$1 == "key:" { k = ($2 == "") ? "-" : $2 }
	$1 == "hash:" { print length($2) / 2, k, m > in_; print $2 > out_ }
' in_="$out/kat.in" out_="$out/kat.out" "$vec/blake2b-kat.txt"
[ "$(wc -l < "$out/kat.out")" -eq 256 ] || { echo "blake2b: kat parse FAIL"; fail=1; }
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

# differential corpus against python3 hashlib.blake2b
if command -v python3 > /dev/null 2>&1; then
	python3 "$here/oracle.py" diff "$seed" "$out" > /dev/null
	echo "blake2b: differential seed $seed"
	check differential "$out/diff.in" "$out/diff.out"
else
	echo "blake2b: NOTE python3 not found, differential corpus NOT_RUN"
fi

# runcmp BIN IN EXPECT TAG: run BIN < IN into TAG.got, without a pipeline so the exit status is kept.
# Sets res to "same" or "differs" when BIN exited 0 with exactly as many lines as EXPECT, else to
# "abnormal (...)": a trap (exit 100+N), a signal, a launch failure or a short output never counts as
# a detected mismatch.
runcmp() {
	if "$1" < "$2" > "$4.got" 2> "$4.err"; then rc=0; else rc=$?; fi
	if [ "$rc" -ne 0 ]; then
		res="abnormal (exit $rc)"
	elif [ "$(wc -l < "$4.got")" -ne "$(wc -l < "$3")" ]; then
		res="abnormal (output has $(wc -l < "$4.got" | tr -d ' ') of $(wc -l < "$3" | tr -d ' ') lines)"
	elif cmp -s "$4.got" "$3"; then
		res=same
	else
		res=differs
	fi
}

# selfcmp BIN TAG: run BIN selftest. Sets res to "same" (exit 0, grand hash = want), "differs" (the
# documented mismatch outcome: exit 1 with a 64-digit grand hash other than want) or "abnormal (...)".
selfcmp() {
	if "$1" selftest > "$2.got" 2> "$2.err"; then rc=0; else rc=$?; fi
	g=$(cat "$2.got")
	if [ "$rc" -eq 0 ] && [ "$g" = "$want" ]; then
		res=same
	elif [ "$rc" -eq 1 ] && [ "${#g}" -eq 64 ] && [ "$g" != "$want" ]; then
		res=differs
	else
		res="abnormal (selftest exit $rc, output '$g')"
	fi
}

# mutant 1: one flipped expected digit must be reported as a mismatch
awk 'NR == 1 { c = substr($0, 1, 1); $0 = ((c == "0") ? "1" : "0") substr($0, 2) } { print }' \
	"$out/kat.out" > "$out/mut-expect.out"
runcmp "$drv" "$out/kat.in" "$out/mut-expect.out" "$out/mut-expect"
if [ "$res" = differs ]; then
	echo "blake2b: mutant expected-digit detected PASS"
else
	echo "blake2b: mutant expected-digit $res FAIL"
	fail=1
fi

# source mutants: each must build, run normally on the RFC case lines, the KAT and the self-test, and
# disagree with at least one expected result
cat "$out/rfc.in" "$out/kat.in" > "$out/mut.in"
cat "$out/rfc.out" "$out/kat.out" > "$out/mut.out"
mutant() { # mutant NAME FROM TO
	m="$out/mut-$1"
	awk -v from="$2" -v to="$3" '$0 == from { $0 = to; hit++ } { print } END { exit hit != 1 }' \
		"$unit/blake2b.om" > "$m.om" || { echo "blake2b: mutant $1 did not apply FAIL"; fail=1; return 0; }
	build "$m.om" "$m" || { fail=1; return 0; }
	runcmp "$m" "$out/mut.in" "$out/mut.out" "$m.cases"
	r1=$res
	selfcmp "$m" "$m.self"
	r2=$res
	case "$r1 $r2" in
	*abnormal*)
		echo "blake2b: mutant $1 ran abnormally: cases $r1, selftest $r2 FAIL"
		fail=1
		;;
	*differs*)
		echo "blake2b: mutant $1 detected PASS"
		;;
	*)
		echo "blake2b: mutant $1 NOT detected FAIL"
		fail=1
		;;
	esac
}
mutant iv0 "put w 40 7640891576956012808" "put w 40 7640891576956012809"
mutant final-flag "b2bcomp w 1" "b2bcomp w 0"
mutant rot63 "put w b or shr t 63 shl t 1" "put w b or shr t 62 shl t 2"
mutant rounds "for r ulong 12" "for r ulong 10"

exit "$fail"
