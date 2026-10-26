# Node-key signatures (`tkasig`)

Production implementation is Omega only. Semantics follow Tailscale
[v1.102.0 `tka/sig.go`](https://github.com/tailscale/tailscale/blob/v1.102.0/tka/sig.go)
and `Authority.NodeKeyAuthorizedWithDetails` in `tka/tka.go`, fetched 2026-10-25.
The independent trusted-key interface has no dependency on the authority-model unit.

## API

Concatenate `blake2s.om`, `sha512.om`, `ed25519.om`, `cbor.om`, then `tkasig.om`.
All functions carry the `nks` prefix. The library contains no globals or main.

Allocate input `d uchar 65536`, CBOR token table `t ulong 131074`, model
`m ulong 132`, output `o uchar 65536`, digest `h uchar 32`, raw node key
`node uchar 32`, and trusted keys `keys uchar 16384`.

* `nksdec d n t m -> ulong`: 0 means successful typed decoding; 1 means
  rejection, including `n > 65536`. Decoding clears the model. On failure, no
  other API may use that model. Input, token table and model must remain paired.
* `nksser d t m o r omit -> ulong`: canonical serialization of row `r`, normally
  0. `omit=1` excludes **only that row's** Signature, retaining signatures in
  Nested. `omit=0` includes it. Returns byte count, or 65537 for invalid row or
  output capacity exhaustion. Output may be partially written on failure.
* `nkshash d t m r h -> ulong`: BLAKE2s-256 of typed canonical serialization
  with that row's signature omitted; returns 1, or 0 on output overflow.
* `nksauth d t m node keys count -> ulong`: 1 authorizes this raw 32-byte node
  key, 0 rejects. `count` is 0..512, otherwise rejected. Table entry `k` is the
  32-byte Ed25519 public key at `keys[32*k..32*k+32)`, also its TKA KeyID.
  The caller must export only currently trusted, valid `Key25519` authority
  keys; no key kinds, votes, or metadata are encoded in this table. Empty
  authority and removed keys reject. These trusted bytes are never derived
  from the received signature. Duplicate entries are harmless.

Tables are caller-owned workspace, not a public mutable object format. Each
8-word model row holds kind, Pubkey token, KeyID token, Signature token, Nested
presence, WrappingPubkey token, and two reserved words. `m[128]` is row count;
129..131 are serialization scratch. Up to sixteen rows are supported, matching
the upstream CBOR nesting limit. Only the helpers above are consumer APIs.
Input/output buffers must not alias. Invalid attacker bytes return rejection,
not a trap; forged tables and mismatched buffers violate the caller contract.
Canonical data can grow slightly when an absent mandatory kind is reconstructed;
output over 65536 is explicitly rejected rather than truncated.

## Semantics

Typed maps accept unsigned integer or UTF-8 text field names (`1` or `"1"`).
Unknown fields are discarded, and skipped values are only CBOR-wellformedness
checked. Duplicate decoded fields (including integer/text aliases), duplicate
unknown keys, invalid field types, and overflowing uint8 kinds are rejected.
Non-shortest CBOR and unsorted maps are accepted. Byte slices accept byte
strings, arrays of uint8-compatible elements, null and undefined; null/undefined
array elements become zero. As in fxamacker, unsigned integers and CBOR simple
values 0..19 or 32..255 fill SigKind and byte-array elements. Booleans and floats
are not numeric substitutes. Null/undefined structs decode to zero values.
Serialization reconstructs the six typed fields in CTAP2 order, omitting empty
slices and nil Nested. Hashes never use raw received CBOR.

Direct signatures bind the `np`-prefixed binary node key and use ZIP-215 under
a trusted authority key. Rotations bind the outer node key, use **strict** Go
Ed25519 rules under the nested wrapping key, and verify the nested chain.
Wrapping keys inherit across intermediate rotations only when their own value
is empty. Credential signatures use ZIP-215 and certify an indirection key;
they cannot authorize a node alone. Direct/credential signatures cannot nest.
As in the public upstream authorization API, nonempty nested credential Pubkey
must also be a valid binary node key (the rotation-details check).

## Tests

```sh
OMC=$(tools/omc.sh)
sh om/tkasig/test/run.sh "$OMC"
# Regenerate the committed deterministic corpus with Go >=1.26.5:
REGEN=1 GO=/path/to/go1.26.8 sh om/tkasig/test/run.sh "$OMC"
```

Tests use Python 3 for framing and comparison, and Go only for regeneration.
`test/go.mod` and `go.sum` pin `tailscale.com` v1.102.0. The oracle calls real
`Unserialize`, `Serialize`, `SigHash`, and `Authority.NodeKeyAuthorized`.
Deterministic private keys are public test fixtures, not deployment secrets.
The corpus covers direct/credential/rotations, inherited wrapping keys, depth
bounds, ZIP-215 versus strict witnesses, validly signed wrong bindings, revoked
or untrusted identity, per-byte mutations, truncations, typed adversarial CBOR,
and large fields. Each driver must exit normally and return exactly one complete
framed result per input. A source mutant counts only on a completed result
mismatch; traps and incomplete output are harness failures. A dedicated trap
probe proves this distinction. No runtime Go is used by the library.

Qualification on 2026-10-25: the focused suite with `REGEN=1` and Go 1.26.8
returned 0 with `PASS tkasig differential 1135 cases`, nine completed-result
source mutant detections, and rejection of the trapping probe. This includes
all 256 simple-value numbers in both SigKind and byte-array positions, plus
validly signed re-encodings whose kinds or byte fields use simple values.
The corpus uses the pinned module. Startup boundary checks additionally exercised oversized input length,
out-of-range serialization row, oversized/empty trusted-key tables, and
canonical-output overflow (including the sighash rejection path). These are
host-only results, not deployment or constant-time qualification.

### Third-party material and notices

Verification and typed-model semantics are adapted from Tailscale v1.102.0,
Copyright (c) Tailscale Inc & contributors, BSD-3-Clause. The complete upstream
license is included as `test/tailscale.LICENSE`. The Go oracle imports the pinned
upstream module and does not substitute a synthetic verifier.
