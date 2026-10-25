# om/codec: base64, base32 and hex for the Tailnet Lock wire format

The text encodings that Tailnet Lock (TKA) JSON uses, written in Omega (`.om`) and compiled by the
pinned seed-born `omc`. Each one gives the same output as the Go code that the Tailscale client and
`tailscale.com` v1.102.0 use. That includes accepting and rejecting the same malformed inputs.

| Wire field | Go code | Functions |
|---|---|---|
| `[]byte` fields (`GenesisAUM`, `MissingAUMs`, signatures, `DisablementSecret`, ...) | `encoding/json` marshals with `base64.StdEncoding` and unmarshals with `base64.StdEncoding.Decode` | `cdb64enc`, `cdb64dec` |
| AUM hashes (`Head`, `Ancestors`) | `tka.AUMHash` `MarshalText` / `UnmarshalText`: `base32.StdEncoding.WithPadding(base32.NoPadding)` | `cdaumenc`, `cdaumdec`, plus the general `cdb32enc`, `cdb32dec` |
| Node keys (`NodeKey`) | `key.NodePublic` `MarshalText` / `UnmarshalText`: `nodekey:` + hex | `cdnkenc`, `cdnkdec`, plus the general `cdhexenc`, `cdhexdec` |

`codec.om` is a library unit: functions only, no `fn main`, no globals. Every name starts with
`cd`. It needs no other unit. Go appears only in the tests, as the oracle.

## API

```
const cdbad ulong 65537
fn cdb64enc s view uchar 65536 n ulong o edit uchar 65536 to ulong
fn cdb64dec s view uchar 65536 n ulong o edit uchar 65536 to ulong
fn cdb32enc s view uchar 65536 n ulong o edit uchar 65536 to ulong
fn cdb32dec s view uchar 65536 n ulong o edit uchar 65536 to ulong
fn cdhexenc s view uchar 65536 n ulong o edit uchar 65536 to ulong
fn cdhexdec s view uchar 65536 n ulong o edit uchar 65536 to ulong
fn cdaumenc h view uchar 32 o edit uchar 65536 to ulong
fn cdaumdec s view uchar 65536 n ulong h edit uchar 32 to ulong
fn cdnkenc k view uchar 32 o edit uchar 65536 to ulong
fn cdnkdec s view uchar 65536 n ulong k edit uchar 32 to ulong
```

| Function | Input | Result |
|---|---|---|
| `cdb64enc` | bytes `s[0..n)`, `n` 0..49152 | Padded standard base64 in `o`. Returns the length, `4*ceil(n/3)`, at most 65536. |
| `cdb64dec` | text `s[0..n)`, `n` 0..65536 | Returns the decoded byte count, with the bytes in `o`, or `cdbad`. |
| `cdb32enc` | bytes, `n` 0..40960 | Unpadded standard base32. Returns `n/5*8 + (n%5*8+4)/5`, at most 65536. |
| `cdb32dec` | text, `n` 0..65536 | Byte count or `cdbad`. |
| `cdhexenc` | bytes, `n` 0..32768 | Lowercase hex. Returns `2n`. |
| `cdhexdec` | text, `n` 0..65536 | `n/2` or `cdbad`. |
| `cdaumenc` | 32-byte hash | 52 base32 characters. Returns 52. |
| `cdaumdec` | text, `n` 0..65536 | 1 means accepted, with the hash in `h`. 0 means rejected, and `h` is all zero. |
| `cdnkenc` | 32-byte key | `nodekey:` and 64 lowercase hex digits. Returns 72. |
| `cdnkdec` | text, `n` 0..65536 | 1 means accepted, with the key in `k`. 0 means rejected, and `k` is all zero. |

- A decoder never traps on its input text: any malformed text returns `cdbad` or 0. Evidence: in
  every run listed under Evidence, each case ran with the driver exiting 0. 11 runs × 40,102
  cases make 441,122 driver cases. A trap exits 100 + its code, and `run.sh` then fails the check.
- An `n` above the stated maximum breaks the caller's contract. The function traps 3 (program exit
  103) before it writes anything. The six `driver N` calls check this, one past each capacity.
- When a decoder returns `cdbad`, the bytes it already wrote to `o` stay there. The caller discards `o`.
- The decoders take the bytes after JSON unquoting. JSON string escapes (`\n`, `\u0041`, ...) belong
  to the JSON layer. So does the `null` / `""` distinction for a nil or empty `[]byte`: Go's
  `encodeByteSlice` writes a nil slice as `null` (encode.go 824-828).
- `cdaumdec` matches `UnmarshalText` called on a zero `AUMHash`, which is how the client uses it
  (`var remoteHead tka.AUMHash` at `ipn/ipnlocal/tailnet-lock.go` 494-495). When the input has fewer
  symbols than 52, `Decode` writes only the leading bytes, and the rest stay zero.

The other functions are internal: character maps (`cdb64v`, `cdb64c`, `cdb32v`, `cdb32c`,
`cdhexv`, `cdhexc`), byte packing (`cdgetbe`, `cdputbe`), and the base32 decoder pieces
(`cdstrip`, `cdb32q`, `cdb32pad`, `cdb32nb`, `cdb32out`, `cdb32raw`).

## Rules, pinned to source

Sources: Go go1.26.0 `src/encoding/{json,base64,base32,hex}` and `tailscale.com` v1.102.0 (commit
`35283c95445fb198af1ce708dac05714bdfaa037`). Both were fetched with the Go module proxy on
2026-10-25. The line numbers below are from those files.

### base64 (`[]byte` in JSON)

- **Encoding.** `encodeByteSlice` (json/encode.go 824-834) calls `base64.StdEncoding.AppendEncode`.
  That is RFC 4648 section 4 with the alphabet `A-Z a-z 0-9 + /` and `=` padding.
- **Decoding.** `literalStore` (json/decode.go 945-956) calls
  `base64.StdEncoding.Decode(b, s)` into `DecodedLen(len(s))` bytes. Any error rejects the field.
  This applies to the default build, where `decode.go` has `//go:build !goexperiment.jsonv2`.
  There is **no** `RawStdEncoding` fallback and no `Strict()`. The v2 code under `GOEXPERIMENT=jsonv2`
  was not traced end to end.
- **Accepted input** (`decodeQuantum` base64.go 312-407, `Decode` 518-584):
  - CR and LF are skipped everywhere, including between and after the `=` characters
    (base64.go 340, 356-359, 372-375).
  - Without CR and LF, the text must be whole groups of 4 characters. Only the last group may end in
    `xx==` or `xxx=`. A `=` anywhere else, missing padding (`Zg`, `Zg=`), or anything other than CR
    or LF after the padding (`Zg==A`, `Zm8==`) is an error.
  - Non-zero trailing bits are accepted (`Zh==` decodes to `66`), because the strict checks at
    base64.go 394 and 401 run only for `Strict()` encodings.
  - Empty text, or text that is only CR and LF, decodes to zero bytes.
  - Any byte outside the alphabet, including space, tab, NUL and bytes 128..255, is an error.
- `cdb64dec` works in one pass, with the same rules as an explicit state machine. The variable `pd`
  holds the padding state.

### base32 (AUM hashes)

- **The encoding.** `base32StdNoPad = base32.StdEncoding.WithPadding(base32.NoPadding)` (tka/aum.go
  24). That is RFC 4648 section 6 with the alphabet `A-Z 2-7` and no padding.
- **Encoding** (base32.go 121-187). A final 1, 2, 3 or 4 bytes become 2, 4, 5 or 7 characters
  (`EncodedLen` 284-289).
- **Decoding.** `DecodeString` (base32.go 421-426) first strips CR and LF everywhere
  (`stripNewlines` 545-555). Then `decode` (305-386) runs. Because the padding is `NoPadding`, Go
  behaves like this, and `cdb32dec` copies it:
  - Lowercase letters, `0`, `1`, `8`, `9`, `=` and every other byte outside `A-Z 2-7` are errors.
    `=` is not special without padding.
  - A final group of 1, 3 or 6 symbols decodes to **no bytes and no error** (switch at 362-382 has
    no case for them; the end-of-input branch at 320-326 never checks). `M` and `MZX` decode to the
    empty string. `MZXW6YTBO` decodes to `fooba`, and the final `O` is dropped.
  - Non-zero trailing bits are accepted (`MZ` decodes to `66`).
  - The padding test at line 330 compares the input byte with `byte(enc.padChar)`. For `NoPadding`
    (rune -1) that is **byte 255**. A 255 byte after at least 2 symbols of a group, with fewer than
    8 bytes left, is handled as padding:
    - the next `7 - j` bytes must also be 255, and fewer than that is an error (lines 331-341);
    - a group of 3 or 6 symbols before it is an error (line 348);
    - bytes after the checked ones are not read, so `MY` + six 255 bytes + `MY` decodes to `66`.

    `cdb32pad` copies this exactly. Through JSON, byte 255 cannot reach `UnmarshalText`: Go's
    JSON unquoting replaces invalid UTF-8 with U+FFFD. The decoder accepts it anyway, because it
    matches Go's `Decode` and not a guess about where its input comes from.
- **`tka.AUMHash.UnmarshalText`** (tka/aum.go 33-41). It first requires
  `DecodedLen(len(text)) == 32`, computed on the raw length before CR and LF are stripped. The
  `NoPadding` `decodedLen` (base32.go 582-587) is `n/8*5 + n%8*5/8`. That equals 32 only for
  n = 52 (51 gives 31 and 53 gives 33). Then it decodes into the 32 bytes. Consequences, all present
  in the corpus:
  - 51 symbols plus one LF is accepted: the last group of 3 symbols is dropped, so 30 bytes come
    from the text and 2 stay zero.
  - 52 symbols plus an LF (53 bytes) is rejected.
  - Lowercase is rejected.
- **`tka.AUMHash.MarshalText`** (tka/aum.go 44-51): 52 characters.

### hex and node keys

- `hex.EncodeToString` (hex.go 45-53) is lowercase. `hex.DecodeString` (hex.go 87-113, 138-142)
  accepts either case and rejects an odd length or any byte outside `0-9 a-f A-F`.
- **`key.NodePublic.MarshalText`** (types/key/node.go 324-332, util.go `appendHexKey` 56-61)
  writes `nodekey:` (node.go 36) and 64 lowercase hex digits.
- **`key.NodePublic.UnmarshalText`** (node.go 336-338, util.go `parseHex` 70-87, `fromHexChar`
  90-101):
  - the prefix is exactly `nodekey:`, case-sensitive;
  - then exactly 64 characters follow, each a hex digit of either case;
  - there is no whitespace or CR/LF tolerance, so mixed-case digits are accepted and `NODEKEY:` is
    rejected.

  `cdnkdec` checks the 8 prefix bytes against the constant `cdnkpfx` (the big-endian value of
  `nodekey:`).

## Test driver protocol

The driver (`test/driver.om`) reads one case per line on stdin: `OP ARG`.

- `OP` is one of `b64e b64d b32e b32d hexe hexd aume aumd nkye nkyd`.
- `ARG` is the input bytes in hex, or `-` for empty. For a decoder these are the bytes of the text,
  so CR, LF, 255 and any other byte can appear.
- For each case it writes one line: `ok TEXT` for an encoder, and `ok HEX` or `err` for a decoder.
  `-` stands for an empty result. For `aumd`/`nkyd` the driver also checks that a rejected call left
  the 32-byte output all zero.
- It exits 0 at the end of input and 65 on a malformed line.
- `driver N` (N = 1..6) calls one coder with a length one past its capacity, and must exit 103.

`run.sh OMC` does the following:

1. Builds `build/test/codec/driver`.
2. Turns the RFC 4648 section 10 lines into 47 cases:
   - base64: encode and decode;
   - base32: encode to the RFC value with `=` removed, decode that value, and check that the
     padded RFC form is rejected, as Go `NoPadding` rejects `=`;
   - base16: encode to lowercase, and decode the RFC's uppercase.
3. Runs the 249 committed malformed-input cases in `vectors/malformed.txt` against Go's results.
4. Runs the differential corpus, when a `go` command (or `$GO`) can build `gen/oracle` with
   `GOTOOLCHAIN=go1.26.0`. Otherwise it prints `NOTE ... NOT_RUN` and still exits on the static checks.
5. Runs the six over-capacity trap calls.
6. Runs the mutants against the 296 static cases. A mutant counts as detected only when the driver
   runs every case to completion and at least one result differs from the expected one. Running
   to completion means every chunk exits 0 (no trap, no signal, no launch failure) and writes one
   result line per case. Any other outcome fails the suite: a run that does not complete, a short
   output, or identical output. The mutants:
   - expectation mutant: the first expected result changed to `err`;
   - `b64-lower-value`: `a-z` decodes one too high;
   - `b64-no-crlf-skip`: LF is no longer skipped in base64;
   - `b64-pad-after-1`: a single `=` is allowed after 1 symbol instead of 3;
   - `b32-digit-char`: the base32 digit characters are off by one;
   - `b32-pad-byte-eq`: base32 treats `=` as padding, as padded `StdEncoding` does;
   - `b32-pad-dlen6`: a 255-padding after 6 symbols is accepted;
   - `hex-upper-value`: `A-F` decodes one too low;
   - `aum-length`: AUMHash accepts lengths below 52;
   - `nodekey-prefix`: the prefix constant is off by one.

`CODEC_SEED` sets the differential seed (default 4648). The driver holds 16 MiB of input, so
`run.sh` feeds it 1000 lines at a time.

## Vector sources

| Source | Origin |
|---|---|
| `vectors/rfc4648.txt` | The 21 BASE64/BASE32/BASE16 lines of RFC 4648 section 10, copied verbatim. Source: https://www.rfc-editor.org/rfc/rfc4648.txt, fetched 2026-10-25, sha256 `84e14418f795d503be5f34bf23ce4ebaa119e9ec7c9f667d8caeb111385b178f`, lines 652-713. See [Third-party material and notices](#third-party-material-and-notices). |
| `vectors/malformed.txt` | 249 hand-made cases, in 18 named groups (`gen/oracle corpus`). They cover empty input, bad characters, wrong padding, non-zero trailing bits, wrong lengths, mixed case, embedded CR/LF, the base32 255-padding byte, AUMHash length versus CR/LF, and node-key prefix, case and length. Results come from Go go1.26.0 (`gen/vectors.sh`). |
| Differential (`gen/oracle rand SEED`, at test time) | 39,806 cases per seed: (1) 300 rounds of random bytes, 0..4096 long, given to every decoder (1,500 cases); (2) every length 0..2048 for `b64e`, `b32e` and `hexe`, plus decoding each result (12,294); (3) 4,000 mutated encodings for each of `b64d`, `b32d` and `hexd`, with 1..3 edits each: replace, insert, delete, truncate, append, case flip, CR/LF insert, drawing from the alphabet and from `= CR LF space tab NUL 0x80 0xff - _ " \ ! . : g G z Z 0 1 8 9 + / a A` (12,000); (4) 2,000 random hashes and keys, each with `aume`, `nkye`, valid `aumd`/`nkyd`, a mutated `aumd`/`nkyd`, and a 52-byte `aumd` with 1..8 symbols replaced by CR, LF or 255 (14,000); (5) the capacity edges `b64e` 49152, `b32e` 40960 and `hexe` 32768 bytes, plus 65536-character `b64d`/`b32d`/`hexd` inputs that are valid, that end in `!`, or are random bytes (12). |

`gen/oracle/main.go` uses only the standard library and is built with go1.26.0. It contains code
derived from tailscale.com v1.102.0, listed under
[Third-party material and notices](#third-party-material-and-notices). The derived code is there
because that module requires go >= 1.26.5. `gen/tsoracle/` calls the real
`tailscale.com/tka` and `tailscale.com/types/key` at v1.102.0 instead. `gen/check-tailscale.sh`
compares the two referees. It is not part of `run.sh`, because it needs network access and a newer
Go.

### Third-party material and notices

| Copied material | Owner and license | Notice file |
|---|---|---|
| In `gen/oracle/main.go`: `base32StdNoPad`, `aumUnmarshalText`, `parseHex` and `fromHexChar`. They are derived from tailscale/tailscale tag v1.102.0 (commit `35283c95445fb198af1ce708dac05714bdfaa037`), `tka/aum.go` 24 and 33-41 and `types/key/util.go` 70-101. The code is modified: `*[32]byte` instead of `AUMHash`, strings instead of `mem.RO`, and shorter `parseHex` error messages. Each block is marked in the source, from "Derived from tailscale" to "End of tailscale-derived code". The file is `SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause`. | Copyright (c) 2020 Tailscale Inc & contributors; BSD 3-Clause License | `gen/oracle/TAILSCALE.LICENSE`: the upstream LICENSE at v1.102.0, verbatim (sha256 `a7ca6186…a45b`, identical to the LICENSE in the v1.102.0 module zip) |
| The 21 BASE64/BASE32/BASE16 lines in `vectors/rfc4648.txt`, from RFC 4648 section 10 | Copyright (C) The Internet Society (2006), under BCP 78. Section 15, "Copying Conditions" (Copyright (c) 2000-2006 Simon Josefsson), grants permission to use, modify and distribute sections 1, 3, 8, 10, 12, 13 and 14 | `vectors/rfc4648.NOTICE`: the RFC's Copyright Notice, section 15 and Full Copyright Statement, verbatim |

The header of `vectors/rfc4648.txt` names its notice file.

Nothing else in `om/codec` is copied from a third party:

- `codec.om`, `test/driver.om`, the shell scripts and `gen/tsoracle/main.go` are omnet's own.
  `tsoracle` imports Tailscale packages but copies no code from them.
- `codec.om` reproduces the behaviour of Go's `encoding/base64`, `encoding/base32` and
  `encoding/hex` (BSD-3-Clause, The Go Authors). Its `note` lines cite Go source line numbers, and
  `cdb32q`/`cdb32pad` follow the same order of checks as base32.go `decode` so that the error
  cases come out identical. No Go source text is copied into it.
- `vectors/malformed.txt` is generated data, and `gen/tsoracle/go.sum` lists module hashes.

## Evidence (2026-10-25, linux arm64 host)

```
$ GO=go sh om/codec/test/run.sh "$(tools/omc.sh)"     # go 1.26.8 on PATH, runs go1.26.0
codec: omc sha256 734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61
codec: codec.om sha256 b3a2de16db05eaac663df2c1cca63c033309eb4705382634a9ed793e6b201b55
codec: driver sha256 2ebf7d063f0a7a90ad4b6e1cc267e0148887a3310b32b73c1cd46e63f2eddcc5
codec: rfc4648 47/47 PASS (42 ok, 5 err)
codec: malformed 249/249 PASS (112 ok, 137 err)
codec: oracle go version go1.26.0 linux/arm64, seed 4648
codec: differential 39806/39806 PASS (25209 ok, 14597 err)
codec: over-capacity call 1 traps 3 PASS
  ... calls 2..6 likewise PASS
codec: mutant expected-result detected PASS (1 of 296 results differ)
codec: mutant b64-lower-value detected PASS (27 of 296 results differ)
codec: mutant b64-no-crlf-skip detected PASS (18 of 296 results differ)
codec: mutant b64-pad-after-1 detected PASS (11 of 296 results differ)
codec: mutant b32-digit-char detected PASS (4 of 296 results differ)
codec: mutant b32-pad-byte-eq detected PASS (15 of 296 results differ)
codec: mutant b32-pad-dlen6 detected PASS (1 of 296 results differ)
codec: mutant hex-upper-value detected PASS (11 of 296 results differ)
codec: mutant aum-length detected PASS (3 of 296 results differ)
codec: mutant nodekey-prefix detected PASS (7 of 296 results differ)
```

The run exited with code 0 and took about 1.4 s.

Other runs:

| Run | Result |
|---|---|
| `CODEC_SEED` = 1..10 | 39806/39806 each. Together with seed 4648 that is 437,866 differential cases (11 × 39,806). |
| `PATH=/usr/bin:/bin` (no Go) | RFC, corpus, traps and mutants PASS. Differential NOT_RUN. Exit 0. |
| `gen/check-tailscale.sh` (oracle go1.26.0, tsoracle go1.26.8 with tailscale.com v1.102.0) | `aume`/`aumd`/`nkye`/`nkyd` lines: corpus 58/58, rand seeds 1, 2 and 3 14600/14600 each. The two referees are identical. |
| Throwaway mutant `ret 63` → `trap 9` in `cdb64v`, appended to `run.sh` once and then removed | `codec: mutant zz-throwaway-trap did not run to completion (exit 109) FAIL`, `run.sh` exit 1. A trapping mutant fails the suite; it is not counted as detected. |

Hashes:

| Item | sha256 |
|---|---|
| omega-mv pin | `acb3f15cdc691b1b046b48b0dad0f9255a12ba4b` (commit) |
| omc | `734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61` |
| `codec.om` | `b3a2de16db05eaac663df2c1cca63c033309eb4705382634a9ed793e6b201b55` |
| `test/driver.om` | `c7fdb4e633b13d358582d5218c7a755a6bea4bc6b6a68f272b47fcc943aeed04` |
| driver binary | `2ebf7d063f0a7a90ad4b6e1cc267e0148887a3310b32b73c1cd46e63f2eddcc5` |
| `vectors/rfc4648.txt` | `c022f1ba1aa15451c29188086461ceb1ee5b7b60f4deff1eb47ed149a23b37e5` |
| `vectors/rfc4648.NOTICE` | `25fb7ac673a9552abf668e7a88e029299f44f6e9b45ff43160e50941ef79c7b3` |
| `gen/oracle/TAILSCALE.LICENSE` | `a7ca6186a7963a0a60740f6047760eecd7a0234e8c38bd7e1e0bbcb324bda45b` |
| `vectors/malformed.txt` | `8abed84be2f8bd56b0b29b092ff6cb01e2a1397172df8177ef6704044e18285f` |

These are host runs only. They are not hardware qualification.

## Limits

- **Not constant-time-audited.** The decoders branch on every input byte. Omega gives no timing
  guarantee, and no timing was measured. Base64 and hex of secrets (`DisablementSecret`) go through
  these branches.
- Capacities: decoder text 65536 bytes, base64 encoder input 49152, base32 40960, hex 32768. The
  TKA design caps request bodies at 64 KiB, so one field always fits.
- No streaming API and no offset parameters: input starts at `s[0]` and output at `o[0]`.
- The JSON layer (unquoting, `null`, field names) is not here.
- The jsonv2 experiment path (`GOEXPERIMENT=jsonv2`) and Tailscale's own Go toolchain fork were
  not examined. The rules follow the standard go1.26.0 default build.
