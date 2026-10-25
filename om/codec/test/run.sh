#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# om/codec test suite. Usage: sh om/codec/test/run.sh OMC
# Builds codec.om + test/driver.om with the pinned omc into build/test/codec/, then runs:
#   - the RFC 4648 section 10 vectors (encode and decode, base64, base32 without padding, base16);
#   - the committed malformed-input corpus with Go go1.26.0's results (vectors/malformed.txt);
#   - when a Go toolchain can run go1.26.0, the seeded differential corpus of gen/oracle;
#   - six over-capacity calls, each of which must trap 3 (exit 103);
#   - one expectation mutant and nine library mutants, each of which must be detected.
# Exit 0 only when every check passes. CODEC_SEED sets the differential seed (default 4648);
# GO names the go command (default go).
set -eu
omc=${1:?usage: run.sh OMC}
here=$(cd "$(dirname "$0")" && pwd)
unit=$(dirname "$here")
root=$(cd "$unit/../.." && pwd)
out="$root/build/test/codec"
vec="$here/vectors"
seed=${CODEC_SEED:-4648}
go=${GO:-go}
rm -rf "$out"
mkdir -p "$out"
fail=0

build() { # build LIBRARY OUTPUT
	cat "$1" "$here/driver.om" | "$omc" > "$2" 2> "$2.err" || {
		echo "codec: omc failed on $1: $(cat "$2.err")"
		return 1
	}
	chmod +x "$2"
}

# runcases BINARY INPUT OUTPUT: feed INPUT in chunks of 1000 lines (the driver holds 16 MiB).
# Returns 1 when any chunk exits non-zero (a trap exits 100 + code, a signal 128 + number, a launch
# failure 126 or 127); rc then holds that exit status.
runcases() {
	rc=0
	rm -f "$out"/chunk.*
	split -l 1000 "$2" "$out/chunk."
	: > "$3"
	for c in "$out"/chunk.*; do
		[ -f "$c" ] || continue
		"$1" < "$c" >> "$3" 2> "$3.err" || { rc=$?; return 1; }
	done
}

# detects NAME BINARY EXPECTED: a mutant is detected only when BINARY ran every static case to
# completion (every chunk exit 0, one result line per case) and at least one result differs from
# EXPECTED. A trap, signal, launch failure or short output fails the suite instead.
detects() {
	if ! runcases "$2" "$out/all.in" "$out/$1.got"; then
		echo "codec: mutant $1 did not run to completion (exit $rc) FAIL"
		fail=1
		return 0
	fi
	want=$(wc -l < "$3" | tr -d ' ')
	got=$(wc -l < "$out/$1.got" | tr -d ' ')
	if [ "$got" -ne "$want" ]; then
		echo "codec: mutant $1 gave $got of $want results FAIL"
		fail=1
	elif cmp -s "$out/$1.got" "$3"; then
		echo "codec: mutant $1 NOT detected FAIL"
		fail=1
	else
		d=$(paste -d '|' "$out/$1.got" "$3" | awk -F'|' '$1 != $2' | wc -l | tr -d ' ')
		echo "codec: mutant $1 detected PASS ($d of $want results differ)"
	fi
}

# check NAME INPUT EXPECTED: the driver's output must equal EXPECTED byte for byte
check() {
	n=$(wc -l < "$3" | tr -d ' ')
	if runcases "$drv" "$2" "$out/$1.got" && cmp -s "$out/$1.got" "$3"; then
		echo "codec: $1 $n/$n PASS ($(grep -c '^ok' "$3") ok, $(grep -c '^err' "$3") err)"
	else
		echo "codec: $1 FAIL ($(cmp "$out/$1.got" "$3" 2>&1 || true))"
		fail=1
	fi
}

drv="$out/driver"
build "$unit/codec.om" "$drv"
echo "codec: omc sha256 $(sha256sum "$omc" | cut -d' ' -f1)"
echo "codec: codec.om sha256 $(sha256sum "$unit/codec.om" | cut -d' ' -f1)"
echo "codec: driver sha256 $(sha256sum "$drv" | cut -d' ' -f1)"

# RFC 4648 section 10: NAME("input") = "output"
awk -F'"' '
	BEGIN { for (i = 32; i < 127; i++) ord[sprintf("%c", i)] = i }
	function hex(s,   r, i) {
		if (s == "") return "-"
		r = ""
		for (i = 1; i <= length(s); i++) r = r sprintf("%02x", ord[substr(s, i, 1)])
		return r
	}
	function ok(s) { return "ok " ((s == "") ? "-" : s) }
	/^BASE64\(/ {
		print "b64e", hex($2) > in_; print ok($4) > out_
		print "b64d", hex($4) > in_; print ok(hex($2)) > out_
	}
	/^BASE32\(/ {
		s = $4; gsub(/=/, "", s)
		print "b32e", hex($2) > in_; print ok(s) > out_
		print "b32d", hex(s) > in_; print ok(hex($2)) > out_
		if (s != $4) { print "b32d", hex($4) > in_; print "err" > out_ }
	}
	/^BASE16\(/ {
		print "hexe", hex($2) > in_; print ok(tolower($4)) > out_
		print "hexd", hex($4) > in_; print ok(hex($2)) > out_
	}
' in_="$out/rfc.in" out_="$out/rfc.out" "$vec/rfc4648.txt"
[ "$(wc -l < "$out/rfc.out")" -eq 47 ] || { echo "codec: rfc4648 parse FAIL"; fail=1; }
check rfc4648 "$out/rfc.in" "$out/rfc.out"

# committed malformed-input corpus: OP ARG RESULT...
awk '/^#/ { next } { print $1, $2 > in_; $1 = ""; $2 = ""; sub(/^  /, ""); print > out_ }' \
	in_="$out/mal.in" out_="$out/mal.out" "$vec/malformed.txt"
check malformed "$out/mal.in" "$out/mal.out"

# differential corpus against the go1.26.0 oracle
if command -v "$go" > /dev/null 2>&1 &&
	(cd "$here/gen/oracle" && GOTOOLCHAIN=go1.26.0 "$go" build -o "$out/oracle" .) > "$out/oracle.log" 2>&1; then
	echo "codec: oracle $(GOTOOLCHAIN=go1.26.0 "$go" version), seed $seed"
	"$out/oracle" rand "$seed" > "$out/diff.in"
	"$out/oracle" < "$out/diff.in" > "$out/diff.out"
	check differential "$out/diff.in" "$out/diff.out"
else
	echo "codec: NOTE go1.26.0 oracle unavailable ($go), differential corpus NOT_RUN"
fi

# over-capacity calls trap 3: program exit 103
for t in 1 2 3 4 5 6; do
	set +e
	"$drv" "$t" > /dev/null 2>&1
	rc=$?
	set -e
	if [ "$rc" -eq 103 ]; then
		echo "codec: over-capacity call $t traps 3 PASS"
	else
		echo "codec: over-capacity call $t exit $rc FAIL"
		fail=1
	fi
done

# every static case in one file, for the mutants
cat "$out/rfc.in" "$out/mal.in" > "$out/all.in"
cat "$out/rfc.out" "$out/mal.out" > "$out/all.out"

# expectation mutant: one flipped expected result must be reported by the unmodified driver
awk 'NR == 1 { $0 = "err" } { print }' "$out/all.out" > "$out/mut-expect.out"
detects expected-result "$drv" "$out/mut-expect.out"

# library mutants: each must build, run every static case, and disagree with at least one
mutant() { # mutant NAME FROM TO
	m="$out/mut-$1"
	awk -v from="$2" -v to="$3" '$0 == from { $0 = to; hit++ } { print } END { exit hit != 1 }' \
		"$unit/codec.om" > "$m.om" || { echo "codec: mutant $1 did not apply FAIL"; fail=1; return 0; }
	build "$m.om" "$m" || { fail=1; return 0; }
	detects "$1" "$m" "$out/all.out"
}
mutant b64-lower-value "ret sub c 71" "ret sub c 70"
mutant b64-no-crlf-skip "if or eq c 10 eq c 13" "if eq c 13"
mutant b64-pad-after-1 "if eq j 3" "if eq j 1"
mutant b32-digit-char "ret uchar add v 24" "ret uchar add v 23"
mutant b32-pad-byte-eq "if and eq c 255 and ge j 2 lt sub l p 8" "if and eq c 61 and ge j 2 lt sub l p 8"
mutant b32-pad-dlen6 "if or eq j 3 eq j 6" "if eq j 3"
mutant hex-upper-value "ret sub c 55" "ret sub c 54"
mutant aum-length "if ne n 52" "if gt n 52"
mutant nodekey-prefix "const cdnkpfx ulong 7957689453343242554" "const cdnkpfx ulong 7957689453343242555"

exit "$fail"
