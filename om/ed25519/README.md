# om/ed25519: Ed25519 signature verification in Omega

`ed25519.om` verifies Ed25519 signatures (RFC 8032 section 5.1.7). It does not sign and holds no
private keys. It has two rule sets because Tailscale Tailnet Lock (TKA) uses both:

| mode | name | behaves as |
|---|---|---|
| 0 | strict | Go `crypto/ed25519.Verify` (go1.26.0) |
| 1 | consensus | ZIP 215, as `github.com/hdevalence/ed25519consensus.Verify` v0.2.0 |

It is a library unit: functions only, no `fn main`, no globals. Every function name starts with
`ed`. SHA-512 comes from the sibling unit `om/sha512/sha512.om` (`s512pre`), which must be
concatenated before this file:

```sh
cat om/sha512/sha512.om om/ed25519/ed25519.om <your program> | "$OMC" > prog
```

## API

```
fn edverify pk view uchar 32 m view uchar 65536 n ulong sg view uchar 64 mode ulong to ulong
```

- `pk`: the 32-byte public key A.
- `m[0..n)`: the message. `n` is at most 65536. A larger `n` traps 3 inside `s512pre`.
- `sg`: the 64-byte signature R || S.
- `mode`: 0 for strict, 1 for consensus. Any other value traps 11.
- Returns 1 when the signature is valid and 0 when it is not.

A signature that is not exactly 64 bytes long cannot be passed in. The caller rejects it first,
as Go does (`verifyWithDom` checks `len(sig) != signatureSize`).

The other functions are internal: field arithmetic `edf*`, points `edp*`, and scalars `edsclt`,
`edmodl`, `edhram`. Their contracts are in the `note` lines of the source.

## Rules (pinned to source)

Both modes compute k = SHA-512(R || A || M) mod L over the bytes exactly as received. They
reject S >= L and decode A the same way, because Go's strict path and ed25519consensus both call
the same permissive `Point.SetBytes`. The modes differ only in how R is checked.

| step | strict (Go crypto/ed25519) | consensus (ed25519consensus) |
|---|---|---|
| S | reject `sig[63]&224 != 0` and S >= L | same |
| A | `Point.SetBytes`: y >= p accepted (reduced mod p), x = 0 with the sign bit set accepted, not on the curve rejected; small-order and mixed-order A accepted | same |
| R | not decoded; the canonical encoding of [S]B - [k]A must equal sig[0..32) byte for byte (so a non-canonical R always fails) | decoded with `Point.SetBytes` (same leniency as A); accept iff [8]([S]B - [k]A - R) is the identity |

The task description asked strict mode to reject non-canonical A. Go does not do that, and this
unit follows Go. In `zip215.txt`, Go strict accepts 12 of the 196 cases, and 4 of those 12 have a
non-canonical A (y >= p). This unit gives the same 12 results.

Line citations (raw files fetched 2026-10-25):

- Go go1.26.0, `src/crypto/ed25519/ed25519.go`: `Verify` at 221-223, `VerifyWithOptions` at
  236-257, `ed25519.NewPublicKey(publicKey)` at 240.
- Go go1.26.0, `src/crypto/internal/fips140/ed25519/ed25519.go`:
  - `newPublicKey` at 141-151, which calls `pub.a.SetBytes` at 146.
  - `verifyWithDom` at 290-327: the `sig[63]&224` check at 295, `SetUniformBytes(hramDigest)` at
    310, `SetCanonicalBytes(sig[32:])` at 315, `Negate` at 321,
    `VarTimeDoubleScalarBaseMult` at 322, and `bytes.Equal(sig[:32], R.Bytes())` at 324.
- Go go1.26.0, `src/crypto/internal/fips140/edwards25519/edwards25519.go`: `Point.SetBytes` at
  145-187. Its comment at 146-149 lists the non-canonical encodings it accepts. `SqrtRatio` is
  called at 172, the `wasSquare == 0` reject is at 173, and the sign select is at 179.
- Go go1.26.0, `.../edwards25519/field/fe.go`: `Element.SetBytes` at 187-218. Its doc at 191-194
  says the top bit is ignored and values 2^255-19 .. 2^255-1 are accepted. `SqrtRatio` is at
  399-421.
- Go go1.26.0, `.../edwards25519/scalar.go`: `SetCanonicalBytes` at 159-171 and `isReduced` at
  178.
- `github.com/hdevalence/ed25519consensus` `ed25519.go` at commit
  15731de461e4d21d6a79d5b7aaf473454f9d2009 (tag v0.2.0): `Verify` at 19-67.
  - Length and `sig[63]&224` checks at 20-26.
  - `SetBytes(publicKey)` at 29 and the hash at 35-40.
  - `SetUniformBytes` at 42, `SetBytes(sig[:32])` at 48, and `SetCanonicalBytes` at 56.
  - `VarTimeDoubleScalarBaseMult` at 61, `Subtract` at 64, `MultByCofactor` at 65, and the
    identity `Equal` at 66.
  - It requires `filippo.io/edwards25519` v1.0.0, whose `Point.SetBytes` (edwards25519.go 142-187)
    and `Element.SetBytes` (field/fe.go 195-198) carry the same accept-non-canonical rule. The test
    oracle builds with v1.1.1, which fixes an unrelated `MultiScalarMult` bug (Dependabot alert 1).
    In v1.1.1, `Point.SetBytes` differs from v1.0.0 only in a comment, and oracle builds on v1.0.0
    and v1.1.1 give identical results on all 818 static cases.

Point decoding follows Go's `SqrtRatio`:

1. r = u v^3 (u v^7)^((p-5)/8), with u = y^2 - 1 and v = d y^2 + 1.
2. Accept if v r^2 = u. If v r^2 = -u, multiply r by sqrt(-1) and accept. Otherwise reject.
3. Take the non-negative r. Negate it when bit 255 is set.

This is RFC 8032 section 5.1.3 without the y < p check and without the rejection of x = 0 when
the sign bit is set.

## Implementation

- **Field GF(2^255-19).** A field element is 16 limbs of radix 2^16, stored in `ulong` cells (the
  TweetNaCl layout, made unsigned).
  - Omega has no 64x64->128 multiply, and signed overflow traps. So every product is at most
    21 x 21 bits, and every limb operation is unsigned.
  - Bounds: a multiply output has limbs <= 65535, except limb 0, which is <= 65573. Subtraction
    computes a + 8p - b limb by limb. Each 8p limb is >= 262136, so the result cannot wrap while
    the subtrahend is a multiply output, a canonical value, or a sum of two of those.
  - Multiply inputs stay below 2^21 per limb, so a column sum is below 16 * 2^42 and the folded
    sum (columns 16..30 times 38) is below 2^52.
  - Two carry passes fold the carry out of limb 15 back into limb 0 with weight 38, because
    2^256 = 38 mod p.
  - The bounds are also checked at run time. `edfsub` traps 9 when a subtrahend limb is above the
    8p limb, and `edfmul` traps 10 when an input limb is >= 2^21. A bound broken by a future edit
    therefore stops the program instead of wrapping silently. Neither trap fired in any run below.
  - Canonical form (`edfcan`): carry until every limb is <= 65535 (value < 2^256 = 2p + 38), then
    subtract p twice, each time only when no borrow results.
- **Workspace.** Every field element and point lives in one `ulong 1024` array at fixed offsets.
  Only one array is passed, which satisfies Omega's rule that the arrays of one call are distinct
  names, and the 6-parameter limit.
- **Inversion and the (p-5)/8 power.** These use the ref10 addition chain: 250 squarings and 11
  multiplications to reach z^(2^250-1), then 5 or 2 more squarings.
- **Points.**
  - Coordinates are extended (X:Y:Z:T).
  - Addition is add-2008-hwcd-3, the unified formula TweetNaCl uses. It is complete for
    Ed25519 and handles the small-order points.
  - Doubling is dbl-2008-hwcd with a = -1, with every output coordinate negated (the same
    projective point). This keeps each subtraction within the bound above.
- **Scalars.**
  - S < L is a byte comparison from the top byte down.
  - k mod L is TweetNaCl `modL`, in signed `long` limbs: any overflow would trap rather than
    wrap.
  - [S]B + [k](-A) is computed by joint double-and-add from bit 252 (S, k < L < 2^253), with
    B + (-A) precomputed.
- **Timing.** Variable time. Every input of verification is public (key, message, signature).
  The code is NOT constant-time-audited, and Omega gives no constant-time guarantee.

## Tests

```sh
sh om/ed25519/test/run.sh "$(tools/omc.sh)"
```

`run.sh` builds `sha512.om + ed25519.om + test/driver.om` into `build/test/ed25519/` and does the
following:

1. Runs every static vector file in both modes.
2. Runs three mutants, each of which must be detected:
   - an expected result flipped;
   - one limb of the constant 2d changed;
   - the consensus cofactor multiplication deleted.

   A mutant counts as detected only when the driver exits with status exactly 1 and prints at
   least one `MISMATCH` line. Any other outcome (exit 0, 65 for bad input, 100+N for a trap, or a
   signal) fails the run, so a mutant that crashes is not mistaken for one that was caught. This
   was checked by temporarily swapping in a mutant that traps 11 on every call: `run.sh` reported
   `FAIL mutant-d2-rfc8032: exit 111, 0 MISMATCH lines` and ended with `ed25519: FAIL`.
3. When python3 has pynacl and cryptography, generates and runs the differential corpus.
   Otherwise it prints a NOTE and skips it.
4. Times one series.

It exits 0 only when every check passes. Environment knobs: `ED_DIFF_COUNT` (2000), `ED_DIFF_SEED`
(1), `ED_BENCH_N` (1000).

Driver line format: `ES EC PKHEX SIGHEX MSGHEX`. ES and EC are the expected strict and consensus
results (`0`, `1`, or `-` to skip that mode). Lines starting with `#` are comments.

### Vector sources (fetched 2026-10-25)

| file | cases | source | expected |
|---|---|---|---|
| `vectors/rfc8032.txt` | 24 | RFC 8032 section 7.1 (https://www.rfc-editor.org/rfc/rfc8032.txt, sha256 `ed63657f…c4c3`): TEST 1, 2, 3, 1024, SHA(abc), plus one flipped bit in R, in S, in pk, and in the message (not TEST 1: empty message) | 1 for the 5 vectors, 0 for the 19 flips, in both modes |
| `vectors/zip215.txt` | 196 | `zip215_test.go` of ed25519consensus at 15731de4 (https://github.com/hdevalence/ed25519consensus/blob/15731de461e4d21d6a79d5b7aaf473454f9d2009/zip215_test.go, sha256 `7008831b…34bd`), message "Zcash" | consensus 1 for all 196 (from the source); strict = Go 1.26.0 run as referee (12 accept) |
| `vectors/wycheproof.txt` | 198 | Wycheproof `testvectors_v1/ed25519_test.json` at a3d5d142 (https://github.com/C2SP/wycheproof/blob/a3d5d1423f2592d6646836a45a21a1b209da9f4d/testvectors_v1/ed25519_test.json, sha256 `ea80ffeb…74b3`) | strict = Wycheproof result for valid/invalid; Go agrees on every one |
| `vectors/edge.txt` | 400 | generated by `gen/vectors.py` (seed 20261025) | Go 1.26.0 strict and ed25519consensus v0.2.0, run as referees |

Notes on the Wycheproof and edge vectors:

- **Wycheproof, 210 tests in total.** 117 valid, 64 invalid, 29 acceptable.
  - 12 invalid tests (tcId 30-41) have signatures that are not 64 bytes. They cannot be passed to
    `edverify` and are listed in the file header.
  - The 29 acceptable tests (flags MixedOrderPublicKey and SmallOrderPublicKey, tcId 152-180) are
    all accepted by Go strict and by consensus. This unit accepts them too.
  - Consensus expectations for Wycheproof come from ed25519consensus run as referee.
- **Edge vectors.** These are RFC 8032 signatures made by the pure-Python signer in
  `gen/vectors.py`, pushed into the corners where strict and consensus differ:
  - S + L;
  - R and/or A plus a point of order 8, hashed as sent;
  - small-order A and R with S = 0;
  - random A or R bytes;
  - high bits of S set.

  Go strict accepts 22 of them and consensus accepts 200.

`gen/vectors.py SRC ORACLE OUT` regenerates the four files and the third-party notices from the
pinned upstream files and the referee in `gen/oracle/`. The referee is a 44-line Go program that
calls `crypto/ed25519.Verify` and `ed25519consensus.Verify`, built with Go 1.26.0, module
`ed25519consensus` v0.2.0. Go and Python are test referees and generators only. Neither builds
nor implements anything in `ed25519.om`, and `run.sh` needs neither for the static vectors.

`gen/diff.py OUT COUNT SEED` writes the differential corpus. Each keypair has a random message of
0..4096 bytes, signed by pynacl 1.5.0 (even index) or cryptography 41.0.7 (odd index). The
signature is expected valid in both modes. A copy with one random bit of pk || sig || msg flipped
is expected invalid in both modes.

### Third-party material and notices

| copied material | owner and license | notice file |
|---|---|---|
| key/signature hex in `vectors/zip215.txt`, from ed25519consensus `zip215_test.go` | Copyright 2016 Henry de Valence (file header); upstream LICENSE: Copyright (c) 2009 The Go Authors, Copyright (c) 2020 Henry de Valence; BSD 3-clause | `vectors/zip215.LICENSE`, the upstream LICENSE at 15731de4, verbatim (sha256 `789be8b2…6bc7`) |
| test data in `vectors/wycheproof.txt`, converted from `ed25519_test.json` (modified: JSON to line format, tests with signatures that are not 64 bytes left out) | Copyright 2016-2026 The Wycheproof Authors; Apache License 2.0 (no NOTICE file upstream) | `vectors/wycheproof.LICENSE`, the upstream LICENSE at a3d5d142, verbatim (sha256 `58d1e17f…d8bd`) |
| keys, messages and signatures in `vectors/rfc8032.txt`, from RFC 8032 section 7.1 | Copyright (c) 2017 IETF Trust and the document authors; IRTF stream, under BCP 78 and the IETF Trust Legal Provisions | `vectors/rfc8032.NOTICE`, the RFC's Copyright Notice section, verbatim |

Each vector file's header names its notice file. `vectors.py` copies the two LICENSE files from
SRC and cuts the RFC notice from the RFC text, so regeneration keeps them.

The RFC 8032 boilerplate has no Code Components clause (it is an IRTF-stream document). I have not
determined whether test vectors in it count as code components under the Trust Legal Provisions.
The notice is included as attribution; whether it is sufficient is not checked.

Not copied: `edge.txt` and the differential corpus come from this unit's own generators. In
`ed25519.om`, the field layout, the `modL` reduction and the add/double formulas follow the
published algorithms of TweetNaCl, and the inversion addition chain follows ref10. Both are
public-domain releases. The Omega code was written for this unit and contains no copied source
text. Go's source is cited by line numbers only.

### Evidence (2026-10-25, Linux arm64 host)

- omc sha256: `734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61` (omega-mv
  acb3f15c, `tools/omc.sh`)
- `ed25519.om` sha256: `7ca5ffb8f9cbf753d6d5a6008ba70270e51c94cbcc43303e29ffbdbb3bb4c167`
- `sha512.om` sha256 at test time: `069a54b75484221bc7dbacfbea744ca9002c295f4f34f2c3905b0776450e3ce2`
- driver binary sha256: `4d939305f7958ff133baec2fcce1b028550d86f5080ff97d2902db4891f77a3f`

Output of `sh om/ed25519/test/run.sh "$(tools/omc.sh)"` (exit 0):

```
PASS rfc8032: cases 24 verifies 48 mismatches 0
PASS zip215: cases 196 verifies 392 mismatches 0
PASS wycheproof: cases 198 verifies 396 mismatches 0
PASS edge: cases 400 verifies 800 mismatches 0
PASS mutant-expectation detected: 2 mismatches
PASS mutant-d2-rfc8032 detected: 10 mismatches
PASS mutant-cofactor-zip215 detected: 157 mismatches
diff: 2000 keypairs, 4000 cases, 5 files, seed 1
PASS diff-00 .. diff-04: 800 cases, 1600 verifies, 0 mismatches each (8000 verifies)
TIME strict: 1000 verifies, 1063530420 ns total, 1063530 ns per verify
TIME consensus: 1000 verifies, 1073996973 ns total, 1073996 ns per verify
```

The timing figure is one series of N = 1000 per mode on RFC 8032 TEST 1 (empty message), measured
with `monons` around each `edverify` call. That is about 1.07 ms per verification on this host.

## Limits

- The message is at most 65536 bytes, because `s512pre` takes a 65536-byte view. A shorter
  message is passed in a 65536-byte array together with its length.
- Verification only: no signing, key generation, batch verification, Ed25519ph, or Ed25519ctx.
- Not constant-time-audited (see above).
- Single-signature speed is about 1.07 ms. No windowed or precomputed-table scalar
  multiplication is used.
