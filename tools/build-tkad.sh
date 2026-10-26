#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Build production Omega only. Optional output path, default build/tkad.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
omc=$(sh "$root/tools/omc.sh")
out=${1:-"$root/build/tkad"}
mkdir -p "$(dirname -- "$out")"
src="$out.om"
cat "$root/om/quantity/quantity.om" "$root/om/blake2s/blake2s.om" "$root/om/sha512/sha512.om" \
    "$root/om/ed25519/ed25519.om" "$root/om/blake2b/blake2b.om" \
    "$root/om/argon2/argon2.om" "$root/om/argon2/argon2pool.om" \
    "$root/om/codec/codec.om" "$root/om/cbor/cbor.om" \
    "$root/om/tka/tka.om" "$root/om/tka/tkastate.om" "$root/om/tka/tkapool.om" \
    "$root/om/tkasig/tkasig.om" "$root/om/json/json.om" "$root/om/store/store.om" "$root/om/store/storepool.om" \
    "$root/cmd/tkad/state.om" "$root/cmd/tkad/helpers.om" "$root/cmd/tkad/rpc.om" \
    "$root/cmd/tkad/adapter.om" "$root/cmd/tkad/socket.om" "$root/cmd/tkad/main.om" > "$src"
"$omc" < "$src" > "$out"
chmod +x "$out"
printf '%s\n' "$out"
