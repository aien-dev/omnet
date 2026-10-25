# om/cbor: the CBOR subset of Tailnet Lock, in Omega

`cbor.om` decodes and encodes CBOR ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)) the way
Tailscale Tailnet Lock (`tailscale.com/tka`, tag `v1.102.0`) does. tka serializes AUMs,
NodeKeySignatures and States with `github.com/fxamacker/cbor/v2` v2.9.0 (the version in tailscale's
`go.mod`): `cbor.CTAP2EncOptions()` to encode and its own `cborDecOpts` to decode.

- The decoder is bounded and not recursive. It reads one input of at most 65536 bytes into a flat
  token table, which the TKA model code walks. It accepts and rejects exactly what fxamacker's
  `Wellformed` check does under tka's options, with the same error class.
- The encoder writes the token table, or any subtree of it, back in CTAP2 canonical form. The
  output is byte-identical to tka's `Serialize` for every structure in the test corpus, so its
  BLAKE2s-256 equals `AUM.Hash()`.
- Input bytes never make it trap. Malformed or hostile input returns an error code. Traps are
  reserved for caller contract violations.

It is a library unit: functions only, no `fn main`, no globals, and every name starts with `cbr`.
Go is used only in the tests, as the oracle. No other language is on the implementation path.

## Files

| Path | Role |
|---|---|
| `cbor.om` | The library unit. |
| `test/driver.om` | Program-mode test driver. It is concatenated after `om/blake2s/blake2s.om` and `cbor.om`. |
| `test/run.sh` | Test suite. Usage: `sh om/cbor/test/run.sh OMC`. |
| `test/gen/oracle/` | Go oracle (`main.go`, `go.mod`, `go.sum`). It imports `tailscale.com/tka` v1.102.0 and fxamacker/cbor v2.9.0. |
| `test/gen/regen.sh` | Rebuilds the four oracle vector files: `sh om/cbor/test/gen/regen.sh GO [OUTDIR]`. |
| `test/vectors/rfc8949-appA.txt` | RFC 8949 Appendix A, Table 6: all 81 rows. |
| `test/vectors/tka-structs.txt` | 1200 structures serialized by tka: 700 AUMs, 300 NodeKeySignatures, 200 States. |
| `test/vectors/hostile.txt` | The hostile corpus, 475 cases, each judged by tka's own `Unserialize`. |
| `test/vectors/fuzz.txt` | 2000 random mutations of tka structures, each judged by Go. |
| `test/vectors/utf8.txt` | 2000 text strings, each judged by Go `utf8.Valid`. |
| `test/vectors/rfc8949.NOTICE` | RFC 8949's Copyright Notice section verbatim, then the TLP 5 BSD License text for Code Components. |
| `test/gen/oracle/tailscale.LICENSE` | tailscale's LICENSE at v1.102.0, verbatim. |

## What tka's CBOR options mean (pinned to source)

Sources, fetched 2026-10-25:
- `tailscale/tailscale` at tag `v1.102.0` (commit `35283c95445fb198af1ce708dac05714bdfaa037`),
  BSD-3-Clause.
- `github.com/fxamacker/cbor/v2` v2.9.0 from the Go module proxy, MIT.

| Question | Answer | Source |
|---|---|---|
| Encoder options | `CTAP2EncOptions`: `Sort: SortCTAP2`, `ShortestFloat: None`, `NaNConvert: None`, `InfConvert: None`, `IndefLength: Forbidden`, `TagsMd: Forbidden`. Nil slices and maps are written as `null` (`f6`), the `NilContainers` default. | tka `aum.go:250`, `sig.go:221`, `tailchonk.go:662`. fxamacker `encode.go:647-656` and `encode.go:387-393`. |
| Map key order | `SortCTAP2 = SortBytewiseLexical`: keys are sorted bytewise-lexically by their encoded bytes, using `bytes.Compare(...) <= 0`. This is not "length first" (`SortCanonical = SortLengthFirst`). Within one major type, shortest-form encodings put length in the head, so the bytewise order is length first and then bytewise. Across types, the head byte decides: unsigned < negative < bytes < text < arrays < maps < simple values. Struct fields are sorted the same way. | `encode.go:176-202`, `encode.go:1375-1400`, `encode.go:1428-1431` |
| Decoder options | `DupMapKey: DupMapKeyEnforcedAPF`, `IndefLength: Forbidden`, `TagsMd: Forbidden`, `MaxNestedLevels: 16`, `MaxArrayElements: 4096`, `MaxMapPairs: 1024`. Everything else is left at its default. | tka `tka.go:22-32`. It is used by `aum.go:269`, `sig.go:240` and `tailchonk.go:428`. |
| Order of checks | `Unmarshal` first runs `wellformed(false, false)` over the whole input, including values it will skip. Only then does it decode into the Go type. | `decode.go:1291-1303` |
| Nesting depth | Arrays and maps count one level each, and the root container is level 1 (tags would count too, but they are forbidden). An item at level 17 is rejected. | `valid.go:126-130`, `valid.go:203-206` |
| Indefinite lengths | Rejected for byte strings, text strings, arrays and maps. A container's depth check runs first. | `valid.go:110-113`, `valid.go:132-135` |
| Tags | All rejected, including tags nested in skipped values. | `valid.go:173-176` |
| Lengths and counts | A length at or above 2^63 fails with an "integer overflow" error. A length past the end of the input fails with an unexpected EOF. An array above 4096 elements or a map above 1024 pairs is rejected before its items are read. | `valid.go:116-153` |
| Simple values and floats | A one-byte simple value below 32 (`f8 00`..`f8 1f`) is rejected. Every other simple value, and every float, is accepted, including NaN and infinity (the `NaNDecode` and `InfDecode` defaults allow them). | `valid.go:308-364`, `decode.go:632-651` |
| Reserved heads and break | Additional information 28-30 is rejected. So is 31 on majors 0, 1 and 6, and a break (`ff`) outside an indefinite item. | `valid.go:366-377` |
| Bytes after the item | Rejected. | `valid.go:93-97` |
| Canonical-only? | **No.** The decoder is lenient about form. It accepts non-shortest heads and unsorted map keys. tka hashes `Serialize()` of the decoded struct (`aum.go` `Hash`), which is canonical, never the received bytes. | hostile class R |
| Unknown fields | Skipped without error (`ExtraReturnErrors` defaults to `ExtraDecErrorNone`). They are well-formedness-checked, but their contents are not type-checked, UTF-8-checked or duplicate-checked. Re-serialization drops them. | `decode.go:2841-2853`, `decode.go:437-438` |
| Duplicate keys | APF ("allow partial fill", then fail) is enforced only where Go decodes. In a struct map, two keys that match the same field are a duplicate. So are two unknown keys equal as Go values; an integer key compares as `int64`, so `2^64-1` and `-1` collide. In a Go map such as `Meta`, keys compare as Go map keys. Duplicates inside skipped values are not checked. | `decode.go:2684-2875` |
| UTF-8 | Text strings are UTF-8-checked only when they are decoded: struct-key text and `Meta` keys and values. | `decode.go:2300-2320` |

## API

The token table is `t view|edit ulong 131074`. Token `i` occupies `t[2i]` (its argument) and
`t[2i+1]` (packed fields: bits 0-2 major type, bits 3-7 additional information, bits 8-24 head
offset, bits 32-48 the index of the token after its subtree). `t[131072]` is the token count and
`t[131073]` is the input length. Tokens are in input pre-order: an array's elements, or a map's
alternating keys and values, follow the container's token.

| Function | Meaning |
|---|---|
| `cbrdec d view uchar 65536 n ulong t edit ulong 131074 to ulong` | Decodes `d[0..n)`. Returns 0, or one of the error codes below. `n > 65536` traps 3. |
| `cbrenc d t o edit uchar 65536 to ulong` | Writes the whole item in CTAP2 canonical form to `o`. Returns the length, which is never more than `n`. |
| `cbrencs d t r o off to ulong` | Writes the subtree of token `r` canonically at `o[off..)` and returns the new offset. Traps 9 before writing if `off + cbrspan t r > 65536`. This is how the model writes `Meta`, `Key` or `State` subtrees inside a struct it rebuilds. |
| `cbrhead o edit uchar 65536 q m v to ulong` | Writes the shortest head for major `m` and argument `v` at `o[q]`. Returns the new offset. It traps 3 if the head does not fit. |
| `cbrmaj`, `cbrai`, `cbrval`, `cbrhoff`, `cbrnext t i` | Token fields. `cbrval` is the integer, the string length, the array count or the map pair count, or the simple value or the raw float bits. A major-1 token holds n for the value -1-n. |
| `cbrpoff t i`, `cbrtend t i`, `cbritems t i`, `cbrspan t i` | The payload offset; the end of the token's own bytes; the number of direct items (2 per map pair); the input bytes of the subtree. |
| `cbrcount t`, `cbrinlen t` | Token count; input length. |
| `cbrmfind t m key to ulong` | The value token of the first pair in map `m` whose key is the unsigned integer `key`, or 0 when there is none. |
| `cbrkeq d t a b`, `cbrdupk d t m` | Key equality under fxamacker's APF rule (integers compare as `int64`, strings by type and bytes); 1 if map `m` has two equal keys. |
| `cbrutf8 d off ln to ulong` | 1 when `d[off..off+ln)` is valid UTF-8 by Go `utf8.Valid` (Unicode Table 3-7: no overlongs, no surrogates, nothing above U+10FFFF). |

The accessors and helpers are defined only after `cbrdec` has returned 0 on the same `t`.

Walking a map, for example an AUM: `k = m + 1`. Then for each of the `cbrval t m` pairs, the value
is `v = cbrnext t k` and the next key is `cbrnext t v`.

### Error codes (`cbrdec`)

Each code is the class of the error fxamacker returns, and the checks run in fxamacker's order, so
the code equals the oracle's classification of `Wellformed` on every vector.

| Code | Meaning | fxamacker error |
|---|---|---|
| 1 | empty input | `io.EOF` |
| 2 | truncated: head argument, string payload or missing items | `io.ErrUnexpectedEOF` |
| 3 | reserved additional information (28-30, or 31 on major 0, 1 or 6) | `SyntaxError` "invalid additional information" |
| 4 | indefinite length | `IndefiniteLengthError` |
| 5 | break code outside an indefinite item | `SyntaxError` "unexpected break" |
| 6 | tag | `TagsMdError` |
| 7 | simple value below 32 in two bytes | `SyntaxError` "invalid simple value" |
| 8 | more than 16 nested arrays/maps | `MaxNestedLevelError` |
| 9 | array of more than 4096 elements | `MaxArrayElementsError` |
| 10 | map of more than 1024 pairs | `MaxMapPairsError` |
| 11 | bytes after the item | `ExtraneousDataError` |
| 12 | length or count >= 2^63 | "... too large, causing integer overflow" |

### Traps (caller contract only)

| Trap | Cause |
|---|---|
| 3 | `n > 65536` in `cbrdec`; an `o` too small for `cbrhead`; `cbrutf8` with `off + ln > 65536`. |
| 9 | `cbrencs` output would pass 65536. |
| 10 | Internal invariant of the map sort: the sorted pairs must end where they began. It never fired in any run. |

### What the model layer must still do

These Go behaviours are typed, so they belong to the AUM/State/NodeKeySignature model built on top
of this unit. Each is a case in `hostile.txt`.

- **Classes D, U and T.** Go rejects these after a successful `Wellformed`:
  - duplicate keys: run `cbrdupk` on every map Go decodes into a struct or a Go map, never on
    skipped values;
  - invalid UTF-8 in struct-key text and `Meta`: run `cbrutf8` on those strings;
  - type errors: a non-map root, a text `MessageKind`, a `MessageKind` of 256 (it overflows
    uint8), negative values for unsigned fields, a byte-string or below -2^63 map key, duplicate
    `Meta` keys, a float where Go expects an integer.
- **Class Q.** Go accepts these, but its re-serialization differs from a generic canonical
  re-encoding:
  - the text key `"1"` matches the field whose tag name is `1` (`cache.go:139-145`,
    `decode.go:2709`);
  - an array of integers fills a `[]byte` (`PrevAUMHash` `[0]` becomes `41 00`);
  - `null` decodes to the zero value: a nil `*Key`, or an empty `Meta` string;
  - unknown keys are dropped on re-serialization. The AUM hash is over the re-serialized bytes, so
    the model must rebuild the struct and hash that, not hash the received bytes.

## Tests

`run.sh` builds the driver and checks:

| Check | What must hold |
|---|---|
| `rfc8949-appA` | The error code equals the Go `Wellformed` class. Every accepted row re-encodes to its own bytes. The rejected rows are the tags (code 6) and the indefinite-length items (code 4). |
| `tka-structs` | Decode, then re-encode, gives tka's `Serialize` bytes exactly. The BLAKE2s-256 (`om/blake2s`) of those bytes equals `AUM.Hash()` for AUMs, and `blake2s.Sum256` otherwise. `cbrmfind` finds key 1. There are no duplicates and all text is valid UTF-8. |
| `hostile` | For every case, the code equals the Go `Wellformed` class. Per class: **W** (well-formedness, both verdicts): Omega accepts if and only if tka's `Unserialize` does; the generator asserts this for every W case. **D**: Go rejects as a duplicate, and `cbrdupk` on the root says 1. **U**: Go rejects as invalid UTF-8, and the driver's every-text-string `cbrutf8` check says 0. **R**: Go accepts non-canonical bytes, and Omega's canonical output equals tka's re-serialization. **T** and **Q**: well-formed, so Omega accepts; these are the model duties above. |
| `fuzz` | The code equals the Go `Wellformed` class, and Omega accepts everything tka's `Unserialize` accepts. |
| `utf8` | `cbrutf8` equals Go `utf8.Valid`. |

A driver trap (exit 100 + code), or fewer output lines than cases, fails the check.

The hostile corpus covers:
- every truncation of a 193-byte AUM (192 cases) and of a 116-byte, 3-deep NodeKeySignature (115);
- empty input, trailing bytes, and two AUMs back to back;
- lengths and counts of 2^64-1, 2^63, 2^63-1, 2^32, 65536 and limit+1, with no content behind them;
- arrays of 4096 and 4097 elements, and maps of 1024 and 1025 pairs;
- nesting at depths 16, 17, 18, 42 and 2002, a 3001-deep root, and NodeKeySignatures built with
  tka's own types nested 16 deep (accepted) and 17 deep (rejected);
- every indefinite form, and an indefinite `PrevAUMHash`;
- tags, including tag 24 wrapping a whole AUM;
- the reserved heads for all 8 majors, and stray breaks;
- every simple-value and float class.

The **oracle cross-check**: `regen.sh` writes every file from fixed PCG seeds, and two runs produced
identical files. `check()` panics unless, for every input that `Wellformed` rejects, tka's real
`AUM.Unserialize` and `NodeKeySignature.Unserialize` fail with the same message. This proves that
the oracle's copy of `cborDecOpts` behaves like tka's own on every judged input.

**Mutants.** Each mutant below is a one-line source change. Each must build, every driver run must
complete normally (exit 0 with one output line per case: no trap, no signal, no launch failure),
and at least one case must differ from its expected result. A mutant whose driver traps or stops
early counts as a FAIL of the suite, not as a detection; this was checked with a throwaway mutant
that traps 3 on the first container (run.sh exit 1, "run ABNORMAL ... FAIL"), then removed:
- `depth-17`, `array-4097`, `map-1023`: the limits;
- `tags-allowed`, `extra-bytes`, `simple-lt32`: reject paths;
- `len-overflow`: the string length check against the input end;
- `shortest-head`: the canonical head width;
- `sort-reversed`, `sort-off`: CTAP2 key order;
- `int64-keys`: the duplicate rule;
- `utf8-surrogates`: the UTF-8 table.

One more mutant flips a digit of an expected hash.

## Vector sources

| File | Source |
|---|---|
| `rfc8949-appA.txt` | https://www.rfc-editor.org/rfc/rfc8949.txt, fetched 2026-10-25. The text file's sha256 is `f1164a5b31a39350ad46abe29b83575eb933ca6c45366989c118b6b1058a214a`. The rows are copied in order. The WF column comes from `oracle judge`. The RFC is Copyright (c) 2020 IETF Trust; the examples are reproduced as test data under the IETF Trust Legal Provisions. |
| `tka-structs.txt`, `hostile.txt`, `fuzz.txt`, `utf8.txt` | `sh om/cbor/test/gen/regen.sh GO`, run 2026-10-25 with go1.26.8 linux/arm64 against `tailscale.com` v1.102.0 and `github.com/fxamacker/cbor/v2` v2.9.0 (both pinned by `test/gen/oracle/go.sum`). The seeds are fixed: gen 1, fuzz 1, utf8 1. |

The generated structures are random but tka-shaped, built from tka's real types:
- **AUMs**: all 5 kinds, plus kinds 0, 6 and 255. Genesis has a nil parent. There are 32-byte and
  odd-length hashes, `Key` with `Meta`, `KeyID`, Checkpoint `State` (one with tka's maximum of 512
  keys, a 21109-byte AUM), `Votes` and `Signatures`.
- **NodeKeySignatures**: kinds 0-4, nested up to 15 levels.
- **States**: nil, empty or filled `DisablementValues` and `Keys`.

Values sit on the head boundaries (0, 23, 24, 255, 256, 65535, 65536, 2^32-1, 2^32, 2^64-1). Byte
lengths are 0, 23-25, 254-257 and 32. Text includes 2-, 3- and 4-byte UTF-8, with strings of up to
139 characters.

The task asked for go1.26.0. The oracle needs go >= 1.26.5, because tailscale.com v1.102.0's
`go.mod` says `go 1.26.5`, and go1.26.0 refuses it:
`go: go.mod requires go >= 1.26.5 (running go 1.26.0; GOTOOLCHAIN=local)`. The vectors were
therefore made with go1.26.8. The CBOR code is fxamacker's, so the Go release does not affect the
bytes [INFERENCE].

### Third-party material and notices

| copied material | owner and license | notice file |
|---|---|---|
| the 81 encoded examples and their diagnostic notation in `test/vectors/rfc8949-appA.txt`, from RFC 8949 Appendix A, Table 6, treated as Code Components | Copyright (c) 2020 IETF Trust and the persons identified as the document authors; IETF stream, under BCP 78 and the IETF Trust Legal Provisions; as Code Components, under the Revised BSD License of TLP 5 section 4.c | `test/vectors/rfc8949.NOTICE`: the RFC's Copyright Notice section (lines 42-55 of the RFC text) verbatim, then the TLP 5 section 4.c BSD License text with "Copyright (c) 2020 IETF Trust and the persons identified as authors of the code" (sha256 `c4c2b526…4d43`) |
| the `cborDecOpts` literal (six option values) transcribed into `test/gen/oracle/main.go` as `tkaDecOpts`, between `BEGIN derived` and `END derived` comments | Copyright (c) 2020 Tailscale Inc & contributors; BSD 3-Clause | `test/gen/oracle/tailscale.LICENSE`, the LICENSE of the `tailscale.com` v1.102.0 module, verbatim (sha256 `a7ca6186…a45b`) |

RFC 8949 is an IETF-stream document, and its notice requires Code Components to carry the
Simplified BSD License text that Trust Legal Provisions section 4.e refers to. Appendix A is a
table of examples, not marked as code. To be safe it is treated as a Code Component anyway.

The license text in `rfc8949.NOTICE` was fetched on 2026-10-25 from
https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/ (HTML page, sha256
`d289f6a5…4c56`). Section 4.e permits reproducing the full BSD License text of section 4.c, and
that is what the file does. The words are verbatim. The year 2020 replaces `<insert year>`. Line
breaks and `-` list markers stand in for the page's HTML layout.

Not copied:
- `cbor.om`, `driver.om`, `run.sh` and `regen.sh` were written for this unit. fxamacker/cbor (MIT)
  and tailscale (BSD 3-Clause) are cited by file and line number only.
- The oracle's `code()` matches three short fxamacker error-message fragments (for example
  "invalid additional information") to classify errors. It copies no fxamacker source.
- The oracle imports `tailscale.com/tka` and `github.com/fxamacker/cbor/v2` as dependencies. It
  does not vendor them; `go.sum` pins their hashes.
- `tka-structs.txt`, `hostile.txt`, `fuzz.txt` and `utf8.txt` are output of this unit's oracle:
  bytes produced by tka's `Serialize` from random inputs, and verdicts from tka's decoder. No
  upstream file is copied into them.

## Evidence (2026-10-25, linux arm64 host)

```
$ CBOR_GO=<go1.26.8> sh om/cbor/test/run.sh "$(tools/omc.sh)"
cbor: omc sha256 734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61
cbor: cbor.om sha256 ef329c70bb5c6ab7f29565c774ef859ddad96ecc2aef9faf7ff5628604326b43
cbor: driver sha256 23f902fe84a4efda95eef372a6c6a644cca7d3f7a43eeb7f54e37ec875cb8488
cbor: rfc8949-appA 81/81 PASS
cbor: tka-structs 1200/1200 PASS nks 300/300 state 200/200 aum 700/700
cbor: hostile 475/475 PASS Q 5/5 D 6/6 R 16/16 T 10/10 U 3/3 W 435/435
cbor: fuzz 2000/2000 PASS
cbor: utf8 2000/2000 PASS
cbor: oracle regeneration identical PASS
cbor: mutant expected-hash detected PASS
cbor: mutant depth-17 detected PASS (1 failing checks)
cbor: mutant array-4097 detected PASS (1 failing checks)
cbor: mutant map-1023 detected PASS (1 failing checks)
cbor: mutant tags-allowed detected PASS (3 failing checks)
cbor: mutant extra-bytes detected PASS (2 failing checks)
cbor: mutant simple-lt32 detected PASS (1 failing checks)
cbor: mutant len-overflow detected PASS (2 failing checks)
cbor: mutant shortest-head detected PASS (3 failing checks)
cbor: mutant sort-reversed detected PASS (3 failing checks)
cbor: mutant sort-off detected PASS (1 failing checks)
cbor: mutant int64-keys detected PASS (1 failing checks)
cbor: mutant utf8-surrogates detected PASS (2 failing checks)
```

The run exited 0 and took about 3.7 s. Without `CBOR_GO`, the regeneration line reads
`NOTE ... NOT_RUN`, and everything else is the same.

Worst-case timings, one run each with bash `time`:

| Input | Time |
|---|---|
| A 61450-byte array of 3 × 4096 two-pair maps (12288 map sorts) | 0.008 s |
| A 62467-byte map of 1024 pairs with 58-byte keys in descending order (worst insertion sort, plus `cbrdupk`) | 0.069 s |

Hashes:

| Item | sha256 |
|---|---|
| `test/driver.om` | `333807d060ddcf8fafeac005ed71cb0dda1c4b09be7b461ba7a3ba13af223909` |
| `test/vectors/tka-structs.txt` | `5c91e692add941d95609296b3f22326a522ccd516a7ba6ae849bc5acfa810436` |
| `test/vectors/hostile.txt` | `738da89f306bb056bc9c8a41e24a32692e150d215eed48f9642b34408993cd6f` |
| `test/vectors/fuzz.txt` | `8e467ff0567a0f41f44407882ced6a53b6c9941cde4216f873fdf124f7404b97` |
| `test/vectors/utf8.txt` | `7c81d144121677de8e9e46a16d1f8ec597d0acf57b4713e64ec02bee0f280ae5` |
| `test/vectors/rfc8949-appA.txt` | `89e759b57884916dfc00ad8e3a464828181f5c692f4165d00c8400f4e7655016` |

These are host runs only. They are not hardware qualification.

## Limits

- **Not constant-time-audited.** The decoder, the sort and the comparisons branch on the data.
  All TKA CBOR is public data.
- Input is at most 65536 bytes, the contract capacity. tkad caps request bodies before parsing.
- Floats and simple values other than false, true, null and undefined are opaque tokens. They are
  re-encoded with their original width and bits. CTAP2 with `ShortestFloatNone` would write a Go
  `float64` as 8 bytes, but no TKA struct has a float field.
- Map sorting is an insertion sort, O(p²) comparisons for p <= 1024 pairs. The measured worst case
  is above.
- No builder for maps from scratch. The model writes its struct maps in key order with `cbrhead`
  (small integer keys sort numerically), and re-encodes received `Meta`, `Key` and `State` subtrees
  with `cbrencs`, which sorts them.
- Duplicate keys inside a map are re-encoded in input order (stable sort). Go cannot produce such a
  map, and the model rejects it with `cbrdupk`.
