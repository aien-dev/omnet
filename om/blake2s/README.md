# om/blake2s: BLAKE2s in Omega

BLAKE2s ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693)), written in Omega (`.om`) and compiled
by the pinned seed-born `omc`. It supports unkeyed and keyed hashing, keys of 0..32 bytes, and digest
lengths of 1..32 bytes. BLAKE2s-256 is the case with no key and a 32-byte digest. Python appears only
in the tests, as an oracle. No other language is on the implementation path.

## Files

| Path | Role |
|---|---|
| `blake2s.om` | Library unit. It has functions only, no `main` and no globals, and every name starts with `b2s`. |
| `test/driver.om` | Program-mode test driver. It is concatenated after the library. |
| `test/run.sh` | Test suite. Usage: `sh om/blake2s/test/run.sh OMC`. |
| `test/oracle.py` | Vector generator built on python3 `hashlib.blake2s`. It is used only for tests. |
| `test/vectors/rfc7693.txt` | The RFC 7693 Appendix B digest of "abc" and the Appendix E grand hash. |
| `test/vectors/blake2s-kat.txt` | The official BLAKE2 KAT file, copied verbatim. |
| `test/vectors/boundary.txt` | 60 block-edge and length cases, with digests from `oracle.py boundary`. |

## API

```
fn b2shash m view uchar 65536 n ulong k view uchar 32 kn ulong outn ulong o edit uchar 32 to void
```

| Parameter | Meaning |
|---|---|
| `m`, `n` | The message. Only `m[0..n)` is read. `n` is 0..65536. |
| `k`, `kn` | The key. Only `k[0..kn)` is read. `kn` is 0..32, and 0 means unkeyed. |
| `outn` | Digest length in bytes, 1..32. |
| `o` | Receives the digest in `o[0..outn)`. `o[outn..32)` is set to 0. |

If `n`, `kn` or `outn` is out of range, the call traps 3 (program exit 103) before it writes `o`.
This was checked with an ad hoc program for `n=65537`, `kn=33`, `outn=0` and `outn=33`.

The message capacity is 65536 bytes, which is the contract value. omc accepts it both as a
`view uchar 65536` parameter and as a `new uchar 65536 0` local array in the caller.

The other functions are internal helpers. All of them take the 64-word working array `w`:

| Function | Purpose |
|---|---|
| `b2sinit` | Sets up the IV and SIGMA. |
| `b2sstart` | Sets h and the parameter block. |
| `b2smw` | Selects the message word. |
| `b2sg` | The G function. |
| `b2sround` | One round. |
| `b2scomp` | The compression function F. |
| `b2sbyte` | Returns one byte of the key-block‖message stream. |
| `b2sload` | Loads a block. |
| `b2sout` | Writes the digest bytes. |

## Standards followed

These are the sections of RFC 7693:

| Section | What it defines | How the code uses it |
|---|---|---|
| 2.1 | BLAKE2s parameters | w=32, r=10, R1..R4 = 16, 12, 8, 7. |
| 2.6 | IV | |
| 2.7 | SIGMA | Each row is packed as sixteen 4-bit indexes. Every row is quoted in a `note` beside its packed value. |
| 3.1 | G | |
| 3.2 | F | |
| 3.3 | Parameter block and padding | `h[0] ^= 0x01010000 ^ (kk << 8) ^ nn`. The key, zero-padded to 64 bytes, is the first block. The last block is zero-padded and carries `t` = total stream bytes and `f0 = 0xFFFFFFFF`. An empty unkeyed message is one zero block with `t = 0`. |

32-bit words are kept in `ulong` cells and masked to 32 bits after every add and rotate.

## Test driver protocol

- `driver` reads one case per line from stdin, in the form `OUTN KEY MSG`. `OUTN` is decimal 1..32.
  `KEY` and `MSG` are hex (either case, even digit count), or `-` for empty. `KEY` holds at most 32
  bytes and `MSG` at most 65536 bytes. For each case the driver writes `2*OUTN` lowercase hex digits
  and a newline. It exits 0 at end of input and 2 on a malformed line.
- `driver selftest` runs the RFC 7693 Appendix E BLAKE2s self-test. That test covers digest lengths
  {16, 20, 28, 32} × input lengths {0, 3, 64, 65, 255, 1024}, unkeyed and keyed, with inputs and keys
  from `selftest_seq`. The driver prints the grand hash and exits 0 only if it equals the RFC's
  `blake2s_res`. The grand hash is the hash of all 48 digests concatenated. That is the same byte
  stream Appendix E feeds through `blake2s_update`.

`run.sh` does the following:

1. Builds `build/test/blake2s/driver`.
2. Converts each vector source to case lines with awk and compares the driver output with `cmp`.
3. Runs the self-test.
4. If python3 is present, generates the differential corpus at test time. If it is absent, the suite
   prints `NOTE ... NOT_RUN` and still checks the static vectors.
5. Runs three mutants:
   - one flipped expected digest digit;
   - IV[0] changed by 1;
   - the final-block flag removed (`b2scomp w 1` → `b2scomp w 0`).

   Each source mutant is rebuilt and must disagree with the RFC vectors.

`B2S_SEED` sets the differential seed. The default is 7693.

## Vector sources

| Source | Where it comes from |
|---|---|
| RFC 7693 Appendix B (`"abc"`) and Appendix E (`blake2s_res`) | https://www.rfc-editor.org/rfc/rfc7693.txt, fetched 2026-10-25. The text file's sha256 is `c943754888364fe29bbd0bb3c71c6658ef392371497eaa4a9d9dde015b0721e5`. |
| BLAKE2 KAT, 256 keyed cases | https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2s-kat.txt at commit `ed1974ea83433eba7b2d95c5dcd9ac33cb847913`, fetched 2026-10-25. The file's sha256 is `a915b96fc07f6ece3b3355a5cbb813dbf9cd0ad37c22a9b89bf11f9c47922418`. Upstream licenses it under CC0 1.0, the OpenSSL License or Apache-2.0, at the user's choice. |
| Boundary cases (`boundary.txt`) | Generated once by `python3 test/oracle.py boundary` (CPython 3.12.3 `hashlib.blake2s`). The key is bytes `00 01 ..`; message byte i is `i mod 251`. The message lengths are 0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 191, 192, 193, 1023, 1024, 1025, 65471, 65472, 65473, 65535 and 65536. Each length is run unkeyed and with a 32-byte key. The file also has keys of 1, 16 and 31 bytes, and digest lengths 1, 2, 16, 20, 28 and 31. |
| Differential corpus (`oracle.py diff SEED`) | Every length 0..1100 twice: unkeyed with a 32-byte digest, and keyed with `kn = 1 + L%32` and `outn = 32 - L%32`. Then 64 seeded-random cases: lengths 65535, 65536 and 62 random lengths in 0..65536, key length 0..32, outn 1..32. That makes 2266 cases. |

## Evidence (2026-10-25, linux arm64 host)

```
$ sh om/blake2s/test/run.sh "$(tools/omc.sh)"
blake2s: omc sha256 734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61
blake2s: driver sha256 c3c34c06f8e8aced3fc1666f3d4bb5dc7f0a8339f8cfeb6952246d8525ef11d3
blake2s: rfc7693-appB 1/1 PASS
blake2s: rfc7693-appE 1/1 PASS (6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe)
blake2s: kat 256/256 PASS
blake2s: boundary 60/60 PASS
blake2s: differential seed 7693
blake2s: differential 2266/2266 PASS
blake2s: mutant expected-digit detected PASS
blake2s: mutant iv0 detected PASS
blake2s: mutant final-flag detected PASS
```

The run exited with code 0 and took about 0.3 s.

Other runs:

| Run | Result |
|---|---|
| Differential seeds 1..5 | 2266/2266 each. |
| `PATH` without python3 | Static vectors and mutants PASS, differential NOT_RUN, exit 0. |

Hashes:

| Item | Value |
|---|---|
| omega-mv pin | `acb3f15cdc691b1b046b48b0dad0f9255a12ba4b` |
| omc sha256 | `734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61` |
| `blake2s.om` sha256 | `f2d79b93a79621db2393d22ed4d51a216f43c286ea32461d73e1681d80b5529f` |
| `test/driver.om` sha256 | `84fb8e43067ab4df71c6c84527efa969d374026c7e635d5712b8d11ece17eefb` |
| driver binary sha256 | `c3c34c06f8e8aced3fc1666f3d4bb5dc7f0a8339f8cfeb6952246d8525ef11d3` |

`note` lines do not change the binary.

These are host runs only. They are not hardware qualification.

## Limits

- **Not constant-time-audited.** Omega gives no timing guarantee, and no timing was measured. For
  example, `b2sbyte` branches on the stream position and the lengths. Branching on data values was
  not audited.
- One-shot only: there is no incremental (init/update/final) API. Messages are limited to 65536
  bytes.
- No salt or personalization parameters, and no tree-hashing parameters. The parameter block holds
  only digest length, key length, fanout 1 and depth 1.
- The block loop has a bound of 2000. At most 1026 blocks are needed.
