#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Argon2i test suite. Usage: sh om/argon2/test/run.sh OMC
# Builds om/blake2b/blake2b.om + argon2.om + argon2pool.om + the driver with the pinned omc into
# build/test/argon2/, runs the RFC 9106 5.2 vector, the committed Go differential corpus (parameter
# sets and Tailnet Lock disablement values), the out-of-range parameter sets and the contract traps;
# then proves the harness discriminates with an expected-digit mutant and eight source mutants.
# Exit 0 only when every vector matches and every mutant is detected.
# ARGON2_ORACLE=PATH (a built test/gen/oracle) adds a fresh random Go differential corpus of
# ARGON2_N cases (default 200) with seed ARGON2_SEED (default 9106); without it that step is NOT_RUN.
set -eu
omc=${1:?usage: run.sh OMC}
here=$(cd "$(dirname "$0")" && pwd)
unit=$(dirname "$here")
root=$(cd "$unit/../.." && pwd)
b2b="$root/om/blake2b/blake2b.om"
out="$root/build/test/argon2"
vec="$here/vectors"
mkdir -p "$out"
fail=0

build() { # build ARGON2_LIB POOL MAIN OUTPUT
	cat "$b2b" "$1" "$2" "$3" | "$omc" > "$4" 2> "$4.err" || {
		echo "argon2: omc failed on $1 $2: $(cat "$4.err")"
		return 1
	}
	chmod +x "$4"
}

# split VECTORFILE NAME: driver input lines (without "case ", without the last field) and the
# expected last field, skipping comments
split() {
	awk '/^#/ { next } { e = $NF; $NF = ""; sub(/ $/, ""); sub(/^case /, ""); print > in_; print e > out_ }' \
		in_="$out/$2.in" out_="$out/$2.out" "$1"
}

# check NAME: run the driver on NAME.in, compare with NAME.out line for line
check() {
	n=$(wc -l < "$out/$1.out" | tr -d ' ')
	if "$drv" < "$out/$1.in" > "$out/$1.got" && cmp -s "$out/$1.got" "$out/$1.out"; then
		echo "argon2: $1 $n/$n PASS"
	else
		echo "argon2: $1 FAIL ($(cmp "$out/$1.got" "$out/$1.out" 2>&1 || true))"
		fail=1
	fi
}

drv="$out/driver"
build "$unit/argon2.om" "$unit/argon2pool.om" "$here/driver.om" "$drv"
echo "argon2: omc sha256 $(sha256sum "$omc" | cut -d' ' -f1)"
echo "argon2: driver sha256 $(sha256sum "$drv" | cut -d' ' -f1)"

split "$vec/rfc9106.txt" rfc9106
check rfc9106
split "$vec/go-diff.txt" go-diff
check go-diff
echo "argon2: go-diff has $(grep -c '^case ' "$vec/go-diff.txt") parameter sets and $(grep -c '^tka ' "$vec/go-diff.txt") tka secrets"
split "$vec/reject.txt" reject
check reject

# fresh random corpus against the Go referee, when one is supplied
if [ -n "${ARGON2_ORACLE:-}" ]; then
	seed=${ARGON2_SEED:-9106}
	python3 "$here/gen/vectors.py" "$ARGON2_ORACLE" random "$seed" "${ARGON2_N:-200}" > "$out/random.txt"
	split "$out/random.txt" random
	echo "argon2: random seed $seed"
	check random
else
	echo "argon2: NOTE ARGON2_ORACLE not set, random Go corpus NOT_RUN"
fi

# contract traps: each must exit 103 (trap 3)
build "$unit/argon2.om" "$unit/argon2pool.om" "$here/trap.om" "$out/trap"
for c in 1 2 3; do
	if "$out/trap" "$c"; then rc=0; else rc=$?; fi
	if [ "$rc" -eq 103 ]; then
		echo "argon2: trap $c exit 103 PASS"
	else
		echo "argon2: trap $c exit $rc FAIL"
		fail=1
	fi
done

# mutant 1: one flipped expected digit must be reported as a mismatch
awk 'NR == 1 { c = substr($0, 1, 1); $0 = ((c == "0") ? "1" : "0") substr($0, 2) } { print }' \
	"$out/go-diff.out" > "$out/mut-expect.out"

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

runcmp "$drv" "$out/go-diff.in" "$out/mut-expect.out" "$out/mut-expect"
if [ "$res" = differs ]; then
	echo "argon2: mutant expected-digit detected PASS"
else
	echo "argon2: mutant expected-digit $res FAIL"
	fail=1
fi

# source mutants: each must build, run normally on the RFC vector and the Go corpus, and disagree
# with at least one expected tag
cat "$out/rfc9106.in" "$out/go-diff.in" > "$out/all.in"
cat "$out/rfc9106.out" "$out/go-diff.out" > "$out/all.out"
mutant() { # mutant NAME FILE FROM TO
	m="$out/mut-$1"
	awk -v from="$3" -v to="$4" '$0 == from { $0 = to; hit++ } { print } END { exit hit != 1 }' \
		"$unit/$2" > "$m.om" || { echo "argon2: mutant $1 did not apply FAIL"; fail=1; return 0; }
	if [ "$2" = argon2.om ]; then
		build "$m.om" "$unit/argon2pool.om" "$here/driver.om" "$m" || { fail=1; return 0; }
	else
		build "$unit/argon2.om" "$m.om" "$here/driver.om" "$m" || { fail=1; return 0; }
	fi
	runcmp "$m" "$out/all.in" "$out/all.out" "$m"
	case "$res" in
	differs) echo "argon2: mutant $1 detected PASS" ;;
	same)
		echo "argon2: mutant $1 NOT detected FAIL"
		fail=1
		;;
	*)
		echo "argon2: mutant $1 ran $res FAIL"
		fail=1
		;;
	esac
}
mutant version argon2.om "a2le32 b 16 19" "a2le32 b 16 16"
mutant type argon2.om "a2le32 b 20 1" "a2le32 b 20 2"
mutant blamka argon2.om "ret add add x y shl mul and x 4294967295 and y 4294967295 1" "ret add x y"
mutant column argon2.om "ret add add mul i 2 mul shr k 1 16 and k 1" "ret add mul i 16 k"
mutant area argon2.om "area = sub area 1" "area = sub area 0"
mutant counter argon2.om "put z 6 add get z 6 1" "put z 6 get z 6"
mutant xor13 argon2pool.om "xr = 1" "xr = 0"
mutant addr128 argon2pool.om "if or eq i i0 eq rem i 128 0" "if eq i i0"

exit "$fail"
