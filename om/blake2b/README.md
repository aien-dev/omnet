# om/blake2b: BLAKE2b in Omega

BLAKE2b ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693)), written in Omega (`.om`) and compiled
by the pinned seed-born `omc`. It supports unkeyed and keyed hashing, keys of 0..64 bytes, and digest
lengths of 1..64 bytes. BLAKE2b-512 is the case with no key and a 64-byte digest. It is the hash
inside Argon2 (`om/argon2`). Python appears only in the tests, as an oracle. No other language is on
the implementation path.

## Files

| Path | Role |
|---|---|
| `blake2b.om` | Library unit. It has functions only, no `main` and no globals, and every name starts with `b2b`. |
| `test/driver.om` | Program-mode test driver. It is concatenated after the library. |
| `test/run.sh` | Test suite. Usage: `sh om/blake2b/test/run.sh OMC`. |
| `test/oracle.py` | Vector generator built on python3 `hashlib.blake2b`. It is used only for tests. |
| `test/vectors/rfc7693.txt` | The RFC 7693 Appendix A digest of "abc" and the Appendix E `blake2b_res` grand hash. |
| `test/vectors/rfc7693.NOTICE` | RFC 7693's Copyright Notice section, verbatim, with a note on what was copied. |
| `test/vectors/blake2b-kat.txt` | The official BLAKE2 KAT file, copied verbatim. |
| `test/vectors/blake2b-kat.LICENSE` | The BLAKE2 repository's `COPYING` (CC0 1.0), verbatim. |
| `test/vectors/boundary.txt` | 60 block-edge and length cases, with digests from `oracle.py boundary`. |

## API

```
fn b2bhash m view uchar 65536 n ulong k view uchar 64 kn ulong outn ulong o edit uchar 64 to void
```

| Parameter | Meaning |
|---|---|
| `m`, `n` | The message. Only `m[0..n)` is read. `n` is 0..65536. |
| `k`, `kn` | The key. Only `k[0..kn)` is read. `kn` is 0..64, and 0 means unkeyed. |
| `outn` | Digest length in bytes, 1..64. |
| `o` | Receives the digest in `o[0..outn)`. `o[outn..64)` is set to 0. |

If `n`, `kn` or `outn` is out of range, the call traps 3 (program exit 103) before it writes `o`.
This was checked with ad hoc programs (the library plus a `main` calling `b2bhash`): `n=65537`,
`kn=65`, `outn=0` and `outn=65` each exit 103; `n=65536, kn=64, outn=64` exits 0.

The other functions are internal helpers. All of them take the 64-word working array `w`:

| Function | Purpose |
|---|---|
| `b2binit` | Sets up the IV and SIGMA. |
| `b2bstart` | Sets h and the parameter block. |
| `b2bmw` | Selects the message word. |
| `b2bg` | The G function. |
| `b2bround` | One round. |
| `b2bcomp` | The compression function F. |
| `b2bbyte` | Returns one byte of the key-block‖message stream. |
| `b2bword` | Reads one little-endian 64-bit word of that stream. |
| `b2bload` | Loads a block. |
| `b2bout` | Writes the digest bytes. |

## Standards followed

These are the sections of RFC 7693:

| Section | What it defines | How the code uses it |
|---|---|---|
| 2.1 | BLAKE2b parameters | w=64, r=12, R1..R4 = 32, 24, 16, 63, block 128 bytes. |
| 2.6 | IV | The SHA-512 IV, quoted in hex in a `note` beside the decimal values. |
| 2.7 | SIGMA | Each row is packed as sixteen 4-bit indexes and quoted in a `note`. Rounds 10 and 11 use rows 0 and 1 (`i mod 10`). |
| 3.1 | G | |
| 3.2 | F | |
| 3.3 | Parameter block and padding | `h[0] ^= 0x01010000 ^ (kk << 8) ^ nn`. The key, zero-padded to 128 bytes, is the first block. The last block is zero-padded and carries `t` = total stream bytes and `f0 = 0xFFFFFFFFFFFFFFFF`. An empty unkeyed message is one zero block with `t = 0`. |

64-bit words are kept in `ulong` cells; Omega `ulong` addition and left shift wrap modulo 2^64, which
is the RFC's arithmetic. The 128-bit counter's high half is always 0, because a stream is at most
65536 + 128 bytes.

## Test driver protocol

- `driver` reads one case per line from stdin, in the form `OUTN KEY MSG`. `OUTN` is decimal 1..64.
  `KEY` and `MSG` are hex (either case, even digit count), or `-` for empty. `KEY` holds at most 64
  bytes and `MSG` at most 65536 bytes. For each case the driver writes `2*OUTN` lowercase hex digits
  and a newline. It exits 0 at end of input and 2 on a malformed line.
- `driver selftest` runs the RFC 7693 Appendix E BLAKE2b self-test. That test covers digest lengths
  {20, 32, 48, 64} × input lengths {0, 3, 128, 129, 255, 1024}, unkeyed and keyed, with inputs and
  keys from `selftest_seq`. The driver prints the grand hash (BLAKE2b with a 32-byte digest of all 48
  digests concatenated) and exits 0 only if it equals the RFC's `blake2b_res`.

`run.sh` does the following:

1. Builds `build/test/blake2b/driver`.
2. Converts each vector source to case lines with awk and compares the driver output with `cmp`.
3. Runs the self-test.
4. If python3 is present, generates the differential corpus at test time. If it is absent, the suite
   prints `NOTE ... NOT_RUN` and still checks the static vectors.
5. Runs five mutants:
   - one flipped expected digest digit;
   - IV[0] changed by 1;
   - the final-block flag removed (`b2bcomp w 1` → `b2bcomp w 0`);
   - rotation R4 changed from 63 to 62;
   - 10 rounds instead of 12.

   Each source mutant is rebuilt and run on the RFC case line plus the KAT, and through the
   self-test. It counts as detected only when every run ended normally and at least one result
   differs from the expected one. A normal end is either exit 0 with one output line per case, or,
   for the self-test, its documented mismatch outcome: exit 1 with a 64-digit grand hash. A trap
   (exit 100+N), a signal, a launch failure or short output makes the mutant FAIL. The runs are
   not piped, so the exit status is kept. The same rule applies to the expected-digit mutant.
   Checked by adding a throwaway mutant that traps on every call (`if gt outn 64` →
   `if gt outn 1`). The suite printed `ran abnormally: cases abnormal (exit 103), selftest abnormal
   (selftest exit 103, output '') FAIL` and exited 1. The throwaway mutant was then removed.

`B2B_SEED` sets the differential seed. The default is 7693.

## Vector sources

| Source | Where it comes from |
|---|---|
| RFC 7693 Appendix A (`"abc"`) and Appendix E (`blake2b_res`) | https://www.rfc-editor.org/rfc/rfc7693.txt, fetched 2026-10-25. The text file's sha256 is `c943754888364fe29bbd0bb3c71c6658ef392371497eaa4a9d9dde015b0721e5`. |
| BLAKE2 KAT, 256 keyed cases | https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt at commit `ed1974ea83433eba7b2d95c5dcd9ac33cb847913`, fetched 2026-10-25. The file's sha256 is `82fcb3cabe8ff6e1452849e3b2a26a3631f1e2b51beb62ffb537892d2b3e364f`. Upstream licenses it under CC0 1.0, the OpenSSL License or Apache-2.0, at the user's choice. Every case uses a 64-byte key and a 64-byte digest; message lengths are 0..255. |
| Boundary cases (`boundary.txt`) | Generated once by `python3 test/oracle.py boundary` (CPython 3.12.3 `hashlib.blake2b`). The key is bytes `00 01 ..`; message byte i is `i mod 251`. The message lengths are 0, 1, 111, 112, 127, 128, 129, 255, 256, 257, 383, 384, 385, 1023, 1024, 1025, 65407, 65408, 65409, 65535 and 65536. Each length is run unkeyed and with a 64-byte key. The file also has keys of 1, 32 and 63 bytes, and digest lengths 1, 2, 20, 32, 48 and 63. |
| Differential corpus (`oracle.py diff SEED`) | Every length 0..1100 twice: unkeyed with a 64-byte digest, and keyed with `kn = 1 + L%64` and `outn = 64 - L%64`. Then 64 seeded-random cases: lengths 65535, 65536 and 62 random lengths in 0..65536, key length 0..64, outn 1..64. That makes 2266 cases. |

## Third-party material and notices

| Copied material | Owner and terms | Notice file |
|---|---|---|
| The "abc" digest (Appendix A) and `blake2b_res` (Appendix E) in `vectors/rfc7693.txt`. The self-test procedure in `test/driver.om` (`selftst`, `seqm`, `seqk`, `mdlen`, `inlen`, `wantres`), a translation of the Appendix E C code into Omega. | Copyright (c) 2015 IETF Trust and the persons identified as the document authors. RFC 7693 is an Independent Submission stream RFC, subject to BCP 78 and the IETF Trust Legal Provisions. | `vectors/rfc7693.NOTICE`: the RFC's Copyright Notice section, verbatim (sha256 `91f11554fcb2e0898435e97667b61c1b44f98af52a14e749ab195db3ef227975`). |
| `vectors/blake2b-kat.txt`, verbatim | BLAKE2 authors. Triple-licensed upstream under CC0 1.0, the OpenSSL License or Apache-2.0; this repository takes it under CC0 1.0. | `vectors/blake2b-kat.LICENSE`: upstream `COPYING` at `ed1974ea`, verbatim (sha256 `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499`). |

The RFC 7693 notice is included for attribution only. Its boilerplate grants no code-component
licence. Section 4 of the IETF Trust Legal Provisions (TLP 5.0) is the section that licenses code
components. TLP 5.0 §8(f) says it does not apply to Independent Submission stream documents; this
was checked against
https://trustee.ietf.org/wp-content/uploads/Corrected-TLP-5.0-legal-provsions.pdf, fetched
2026-10-25, sha256 `b5cbd993d1dae273d7b251db4efc397b4de13451b2156b94d5a901c83c0fb48a`. Whether the
copied test values and the translated self-test count as code components, and whether attribution
is sufficient, has not been determined.

Not copied: the IV and SIGMA constants in `blake2b.om` are the algorithm's defining values,
written out as decimal numbers. The Omega code was written for this unit and contains no copied
source text. `boundary.txt` and the differential corpus come from this unit's own generator.

## Evidence (2026-10-25, linux arm64 host)

```
$ sh om/blake2b/test/run.sh "$(tools/omc.sh)"
blake2b: omc sha256 734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61
blake2b: driver sha256 a3585a97a5918f854d86d312da60635666e1ecacf59d5c2f81d8065a15f91094
blake2b: rfc7693-appA 1/1 PASS
blake2b: rfc7693-appE 1/1 PASS (c23a7800d98123bd10f506c61e29da5603d763b8bbad2e737f5e765a7bccd475)
blake2b: kat 256/256 PASS
blake2b: boundary 60/60 PASS
blake2b: differential seed 7693
blake2b: differential 2266/2266 PASS
blake2b: mutant expected-digit detected PASS
blake2b: mutant iv0 detected PASS
blake2b: mutant final-flag detected PASS
blake2b: mutant rot63 detected PASS
blake2b: mutant rounds detected PASS
```

The run exited with code 0 and took about 0.3 s. Differential seeds 1..5 gave 2266/2266 each.

Hashes:

| Item | Value |
|---|---|
| omega-mv pin | `acb3f15cdc691b1b046b48b0dad0f9255a12ba4b` |
| omc sha256 | `734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61` |
| `blake2b.om` sha256 | `91299627928a67711e520b454dcde5fd9ce3f7cc4f4eebd01bb068cc564d42fd` |
| `test/driver.om` sha256 | `7d638023cf195e87da5bf95234c42960529e04f8275d54548770031d2f6372a3` |
| driver binary sha256 | `a3585a97a5918f854d86d312da60635666e1ecacf59d5c2f81d8065a15f91094` |

`note` lines do not change the binary.

These are host runs only. They are not hardware qualification.

## Limits

- **Not constant-time-audited.** Omega gives no timing guarantee, and no timing was measured. For
  example, `b2bbyte` branches on the stream position and the lengths. Branching on data values was
  not audited.
- One-shot only: there is no incremental (init/update/final) API. Messages are limited to 65536
  bytes.
- No salt or personalization parameters, and no tree-hashing parameters. The parameter block holds
  only digest length, key length, fanout 1 and depth 1.
- The block loop has a bound of 1000. At most 513 blocks are needed.
- Each byte of the stream is fetched through `b2bbyte`, eight calls per word; speed was not a goal.
