# Bounded JSON

`json.om` is an Omega-only, global-free JSON parser and encoder for the daemon's raw TKA requests.
It has no dependencies on another unit. Concatenate it before callers. Parsing is iterative, not
recursive, and retains exact number lexemes rather than converting through floating point.

## Limits and policy

- Input, decoded string/number arena, and output each have a separate 65,536-byte capacity.
- At most 4,095 tokens, counting object keys and container tokens. At most 32 nested containers.
  Scalars inside the 32nd container are accepted. A string of 65,534 ASCII bytes fits as one input
  string; decoded replacement characters can expand invalid input beyond the arena limit.
- At most 256 members per object, independently at every nesting level. The attempted 257th key
  is rejected before its decoding or duplicate scan. This intentionally rejects larger objects
  that Go accepts. It bounds the quadratic duplicate-key scan; the daemon's 64-node signature
  map fits this profile. Arrays remain governed by the overall token bound.
- All JSON grammar is checked, including number grammar, matching delimiters, separators, control
  characters, escapes, and the absence of a second root value or trailing non-whitespace bytes.
- Strings follow Go `encoding/json`: UTF-16 surrogate pairs combine; lone surrogates become U+FFFD;
  invalid UTF-8 is replaced one offending byte at a time. Embedded U+0000 is preserved with an
  explicit length. Valid UTF-8 and literal Unicode are retained.
- **Duplicate decoded object keys are rejected in every object.** This intentionally differs from
  Go's last-value/merge behavior. Escape aliases (`"a"` and `"\u0061"`), invalid UTF-8 aliases and
  lone-surrogate aliases therefore cannot overwrite one another. Equality is case-sensitive; it
  does not perform Unicode normalization. Callers implementing Go's case-insensitive struct-field
  lookup must additionally reject aliases of the same known field. `jsonfind` is exact-case only.
- This unit checks JSON syntax, not the TKA schema. For example `{"GenesisAUM":true}` is valid JSON
  but is not a valid `tailcfg.TKAInitBeginRequest`. The daemon must enforce field types, required
  fields, case aliases, integer destination widths and codec-specific limits. Byte arrays/base64,
  node keys and AUM hashes are decoded by their existing codec/model units.

Bound violations return errors, never attacker-triggered traps. Callers must provide the fixed-size
arrays named in the signatures, use distinct input/arena/token/output arrays, and discard partial
output on failure. Token accessors and `jsonencode` require an unmodified table and arena from a
successful `jsonparse`; a forged token table is a caller contract violation. Only `tok[0]` is valid
following a failed parse (it is zero). Other data is scratch and may contain partial results.

## Parsing API

`jsonparse(raw view uchar 65536, n ulong, tok edit ulong 32768,
          dec edit uchar 65536) -> int`

Returns zero on success, otherwise: 1 syntax, 2 input/decoded-byte bound, 3 token bound,
4 depth bound, 5 duplicate key, 6 object-member bound. Empty input is rejected. No I/O or global state is used.

`tok[0]` is the token count. Root id is 1; zero is the absent-id sentinel. Header slots 1..7
are reserved. Token `id` starts at `id * 8`, with these fields:

| Offset | Meaning |
|---|---|
| 0 | Kind: 1 object, 2 array, 3 string, 4 number, 5 true, 6 false, 7 null |
| 1 | Offset into `dec` for decoded string or raw number lexeme |
| 2 | Byte length; zero for containers, booleans and null |
| 3 | Id immediately after the entire subtree |
| 4 | Parent container id; zero at root |
| 5 | Direct-child count; includes both keys and values for objects |
| 6 | 1 for an object key, otherwise 0 |
| 7 | Internal parser phase; callers must not inspect it |

Children are preorder. An object's children alternate key, value; a key is always a string token
and its value starts at `key_id + 1`. Use a value's subtree-next field to advance to the next key.

- `jsonfind(tok, dec, obj ulong, key view uchar 65536, n ulong) -> ulong`: exact decoded key lookup;
  returns the value id or zero. Only direct members of `obj` are searched.
- `jsoncopy(tok, dec, id ulong, out edit uchar 65536) -> ulong`: copies the token's string/number
  bytes, returning their length; invalid id returns `jsonbad` (65,537).
- `jsonuint(dec, off ulong, n ulong, result edit ulong 1) -> int`: exact unsigned 64-bit decimal
  conversion; zero on success. Rejects negative signs, leading zeros, fractions, exponents,
  whitespace and overflow. Result is zero on failure.
- `jsonint(dec, off ulong, n ulong, result edit long 1) -> int`: exact signed 64-bit conversion,
  including -9,223,372,036,854,775,808 and `-0`; same rejection rules except an optional minus.

No number precision is lost: numbers beyond 64-bit range remain valid JSON tokens but fail the
integer helpers. There is no implicit float conversion or arbitrary exponent computation.

## Encoding API

Every writer returns the next output offset, or `jsonbad` (65,537). That sentinel is sticky through
further writer calls. No writer terminates output with a NUL. Capacity is checked before access;
an error can leave a partial prefix, which must not be sent. Writer helpers do not maintain a JSON
syntax state: punctuation/field sequencing is the caller's responsibility.

- `jsonbyte(out edit uchar 65536, pos ulong, byte uchar) -> ulong`
- `jsonraw(out, pos, src view uchar 65536, n ulong) -> ulong`
- `jsonspan(out, pos, src, off ulong, n ulong) -> ulong`
- `jsonstr(out, pos, src, n ulong) -> ulong`: encode a JSON string, including quotes.
- `jsonquote(out, pos, src, off ulong, n ulong) -> ulong`: same, for an arena span without a copy.
- `jsonu64(out, pos, value ulong) -> ulong`
- `jsoni64(out, pos, value long) -> ulong`
- `jsonencode(tok view ulong 32768, dec view uchar 65536, out edit uchar 65536) -> ulong`:
  compactly encode the parsed tree. Retains member order and number spelling. This is not a
  canonicalization scheme. Output can exceed the input size and fail explicitly.

String output matches Go `json.Marshal(string)`: standard short control escapes, lowercase `\u`
hex, HTML escapes for `<`, `>` and `&`, and escapes for U+2028/U+2029. Invalid UTF-8 becomes
`\ufffd`; a valid U+FFFD scalar remains literal UTF-8, matching Go. Internal helpers all have the
`json` prefix; callers should use the APIs above.

## Focused tests

```sh
GO=/path/to/go1.26.8/bin/go sh om/json/test/run.sh
# Or pass the compiler already verified by tools/omc.sh:
GO=/path/to/go1.26.8/bin/go sh om/json/test/run.sh /path/to/pinned/omc
```

The suite builds with the repository-pinned Omega compiler. Go is a **test oracle only** and is
required for this suite; the module pins `tailscale.com v1.102.0`. Deterministic generated cases
compare complete token metadata/decoded data (a 64-bit rolling fingerprint), exact output bytes,
accept/reject behavior and exact signed/unsigned integer results with Go `encoding/json`. The
oracle uses `Decoder.UseNumber`, independently walks the token stream, and applies only the
explicit resource bounds and duplicate-key policy above.

Coverage includes all eight actual `tailcfg` request types, their responses, map `TKAInfo`, NodeID
values above 2^53 and at the signed limit, nil/empty byte values, arrays, maps, case-insensitive
field decoding, escaped field names, ignored unknown fields, all 256 byte values, malformed and
boundary UTF-8, surrogate pairs, exact integer limits, malformed grammar, and message/token/depth/
member/writer bounds. Tests explicitly distinguish valid generic JSON from a typed tailcfg rejection.
The driver also checks lookup, token copying, offset/length boundaries and sticky writer errors.
`test/vectors.json` supplies independently authored committed golden cases. Generated Go records
and compiled test artifacts live in `build/test/json`, not the production unit.
The member boundary includes 256 accepted and 257 rejected members, both at root and nested.
A measured smoke sends ten full 65,536-byte messages, each with 256 distinct 250-byte keys sharing
a 247-byte prefix. It prints actual wall time for parsing, token hashing and encoding together,
including process startup and pipe I/O; this is not an isolated parser benchmark or a latency SLA.

Six mutants must finish the entire differential run normally and produce at least one wrong
answer: duplicate acceptance, wrong surrogate replacement, depth and member off-by-ones, integer
bound, and HTML escaping. A separate trapping mutant must be classified as abnormal, not counted as a
successful detection. A short output, compiler failure, process signal, trap or timeout fails.
These are host-only tests and make no stock-client deployment claim.

## Third-party material and notices

No upstream implementation or vector text is copied or translated into this unit. Tests import
the upstream Go packages through their pinned modules, which retain their own licenses. The
vectors are independently authored. Format references:

- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259), especially sections 6 and 7.
- [Go encoding/json](https://pkg.go.dev/encoding/json).
- [Pinned tailcfg TKA types](https://github.com/tailscale/tailscale/blob/v1.102.0/tailcfg/tka.go).

References checked against the local pinned sources on 2026-10-25.
