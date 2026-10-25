#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test suite for om/sha512. Usage: sh om/sha512/test/run.sh OMC
# OMC is the pinned seed-born compiler (tools/omc.sh prints its path).
# Exits 0 only when every vector passes and every mutant / negative check fails as expected.
set -eu
omc=${1:?usage: run.sh OMC}
here=$(cd "$(dirname "$0")" && pwd)
unit=$(dirname "$here")
root=$(cd "$unit/../.." && pwd)
out="$root/build/test/sha512"
vec="$here/vectors"
mkdir -p "$out"
total=0
bad=0

say() { printf '%s\n' "$*"; }
fail() { say "FAIL $*"; bad=1; }

# build LIB DRIVER BIN: concatenate the library and a program, compile with omc
build() {
	cat "$1" "$2" > "$3.om"
	if ! "$omc" < "$3.om" > "$3" 2> "$3.err"; then
		say "omc refused $3.om: $(cat "$3.err")"
		return 1
	fi
	chmod +x "$3"
}

# run_ok NAME FILE: the driver must accept every record of FILE
run_ok() {
	if "$out/driver" < "$2" > "$out/$1.out" 2>&1; then
		line=$(tail -n 1 "$out/$1.out")
		n=$(printf '%s\n' "$line" | awk '{print $3}')
		total=$((total + n))
		say "PASS $1: $line"
	else
		fail "$1: $(tail -n 3 "$out/$1.out" | tr '\n' ' ')"
	fi
}

# run_fails NAME FILE WANT: the driver must exit 1 reporting exactly WANT failed checks
run_fails() {
	set +e
	"$3" < "$2" > "$out/$1.out" 2>&1
	rc=$?
	set -e
	got=$(tail -n 1 "$out/$1.out" | awk '{print $5}')
	if [ "$rc" -eq 1 ] && [ "$got" = "$4" ]; then
		say "PASS $1: rejected as expected ($(tail -n 1 "$out/$1.out"))"
	else
		fail "$1: expected exit 1 with $4 failed, got exit $rc: $(tail -n 1 "$out/$1.out")"
	fi
}

build "$unit/sha512.om" "$here/driver.om" "$out/driver" || exit 1
say "omc     sha256 $(sha256sum "$omc" | cut -d' ' -f1)"
say "library sha256 $(sha256sum "$unit/sha512.om" | cut -d' ' -f1)"
say "driver  sha256 $(sha256sum "$out/driver" | cut -d' ' -f1)"

# NIST CAVP byte-oriented .rsp files -> driver records
awk '{ sub(/\r$/, "") }
	/^Len = / { n = $3 / 8 }
	/^Msg = / { m = $3 }
	/^MD = /  { if (n == 0) m = "-"; print "H", n, m, $3 }' \
	"$vec/SHA512ShortMsg.rsp" > "$out/short.txt"
awk '{ sub(/\r$/, "") }
	/^Len = / { n = $3 / 8 }
	/^Msg = / { m = $3 }
	/^MD = /  { print "H", n, m, $3 }' \
	"$vec/SHA512LongMsg.rsp" > "$out/long.txt"
awk '{ sub(/\r$/, "") }
	/^Seed = / { printf "M %s", $3 }
	/^MD = /   { printf " %s", $3; k++ }
	END        { print ""; if (k != 100) exit 1 }' \
	"$vec/SHA512Monte.rsp" > "$out/monte.txt"

run_ok nist-examples "$vec/nist-examples.txt"
run_ok cavp-short "$out/short.txt"
run_ok cavp-long "$out/long.txt"
run_ok cavp-monte "$out/monte.txt"
run_ok oracle-static "$vec/oracle.txt"

# differential corpus against python3 hashlib.sha512, generated now
if command -v python3 > /dev/null 2>&1; then
	seed=${S512_SEED:-1}
	python3 "$here/gen_vectors.py" diff "$seed" > "$out/diff.txt"
	python3 "$here/gen_vectors.py" pre "$seed" > "$out/pre.txt"
	run_ok "hashlib-diff(seed $seed)" "$out/diff.txt"
	run_ok "hashlib-pre(seed $seed)" "$out/pre.txt"
else
	say "NOTE python3 not found: differential corpus against hashlib skipped"
fi

# mutant 1: one expected digest hex digit changed -> exactly 1 failure
awk 'NR == 3 { c = substr($4, 128, 1); $4 = substr($4, 1, 127) (c == "0" ? "1" : "0") } { print }' \
	"$vec/nist-examples.txt" > "$out/mut-expect.txt"
if cmp -s "$vec/nist-examples.txt" "$out/mut-expect.txt"; then
	fail "mutant-expected: mutation did not change the file"
else
	run_fails mutant-expected "$out/mut-expect.txt" "$out/driver" 1
fi

# mutant 2: K[0] changed by one in the library -> every NIST example fails
sed 's/^put k 0 4794697086780616226$/put k 0 4794697086780616227/' "$unit/sha512.om" > "$out/mut-k-lib.om"
if cmp -s "$unit/sha512.om" "$out/mut-k-lib.om"; then
	fail "mutant-constant: mutation did not change the library"
elif build "$out/mut-k-lib.om" "$here/driver.om" "$out/mut-k"; then
	n=$(grep -c '^H ' "$vec/nist-examples.txt")
	run_fails mutant-constant "$vec/nist-examples.txt" "$out/mut-k" "$n"
else
	fail "mutant-constant: build failed"
fi

# negative: a malformed record (odd hex digit count) is refused, not hashed
printf 'H 3 61626 %0128d\n' 0 > "$out/malformed.txt"
run_fails malformed-record "$out/malformed.txt" "$out/driver" 1

# negative: n one past the capacity traps 3 (exit 103)
if build "$unit/sha512.om" "$here/trap.om" "$out/trap"; then
	set +e
	"$out/trap"
	rc=$?
	set -e
	if [ "$rc" -eq 103 ]; then
		say "PASS over-capacity: n = 65537 traps 3 (exit 103)"
	else
		fail "over-capacity: expected exit 103, got $rc"
	fi
else
	fail "over-capacity: build failed"
fi

if [ "$bad" -ne 0 ]; then
	say "sha512: FAIL"
	exit 1
fi
say "sha512: PASS ($total vector checks)"
