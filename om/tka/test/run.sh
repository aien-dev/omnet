#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
OMC=${1:-}
if [ -z "$OMC" ]; then OMC=$("$ROOT/tools/omc.sh"); fi
GO=${TKA_GO:-${GO:-go}}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
cd "$ROOT/om/tka/test/oracle"
GOTOOLCHAIN=local "$GO" build -mod=readonly -o "$TMP/oracle" .
"$TMP/oracle" "$TMP/input" "$TMP/expected" "$ROOT/om/cbor/test/vectors"
cat "$ROOT/om/blake2s/blake2s.om" "$ROOT/om/sha512/sha512.om" "$ROOT/om/ed25519/ed25519.om" "$ROOT/om/cbor/cbor.om" > "$TMP/base.om"
cat "$TMP/base.om" "$ROOT/om/tka/tka.om" "$ROOT/om/tka/tkastate.om" "$ROOT/om/tka/tkapool.om" "$ROOT/om/tka/test/driver.om" > "$TMP/driver.om"
"$OMC" < "$TMP/driver.om" > "$TMP/driver"
chmod +x "$TMP/driver"
"$TMP/driver" < "$TMP/input" > "$TMP/actual"
python3 "$ROOT/om/tka/test/check.py" "$TMP/expected" "$TMP/actual" exact
python3 - "$TMP/driver.om" "$TMP/mutant.om" <<'PY'
import pathlib,sys
s=pathlib.Path(sys.argv[1]).read_text()
old='ret edverify pk msg 32 sg 1'
assert s.count(old)==1
pathlib.Path(sys.argv[2]).write_text(s.replace(old,'ret 1'))
PY
"$OMC" < "$TMP/mutant.om" > "$TMP/mutant"
chmod +x "$TMP/mutant"
"$TMP/mutant" < "$TMP/input" > "$TMP/mutant.actual"
python3 "$ROOT/om/tka/test/check.py" "$TMP/expected" "$TMP/mutant.actual" mutant
"$TMP/oracle" --fixture > "$TMP/fixture.json"
python3 - "$TMP/fixture.json" "$TMP/revocation.input" <<'PY'
import json,pathlib,struct,sys
v=json.loads(pathlib.Path(sys.argv[1]).read_text())
b=bytearray()
for key in ("genesis","signature","node","removal"):
    data=bytes.fromhex(v[key])
    if key != "node":
        b.extend(struct.pack("<I",len(data)))
    b.extend(data)
pathlib.Path(sys.argv[2]).write_bytes(b)
PY
cat "$TMP/base.om" "$ROOT/om/tka/tka.om" "$ROOT/om/tka/tkastate.om" "$ROOT/om/tka/tkapool.om" "$ROOT/om/tkasig/tkasig.om" "$ROOT/om/tka/test/revocation.om" > "$TMP/revocation.om"
"$OMC" < "$TMP/revocation.om" > "$TMP/revocation"
chmod +x "$TMP/revocation"
"$TMP/revocation" < "$TMP/revocation.input"
printf '%s\n' 'tka: PASS cross-unit node-signature revocation'
printf '%s\n' 'tka: PASS (differential model, authority, sync, signature mutant)'
