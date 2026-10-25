# om/argon2: Argon2i in Omega

Argon2i, version 0x13 ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)), written in Omega (`.om`)
and compiled by the pinned seed-born `omc`. It hashes with `om/blake2b`. It takes every RFC input:
password P, salt S, secret K, associated data X, passes t, memory m, lanes p and tag length T.
It also computes the Tailnet Lock disablement value. Tailscale defines that value as
`argon2.Key(secret, "tailscale network-lock disablement salt", 4, 16*1024, 4, 32)`, from
golang.org/x/crypto/argon2, at `tka/state.go:116,129` in tailscale.com v1.102.0. The TKA server
recomputes it to check a submitted disablement secret.

Only Argon2i is implemented. Argon2d and Argon2id are not, because TKA does not use them. Go and
Python appear only in the tests: Go as the referee, Python as the generator of the vector file.

## Why the unit is split in two files

The matrix for the TKA parameters is 16384 blocks of 1024 bytes, which is 16 MiB. Four limits of the
pinned `omc` decide where that memory can live. Each was checked with a probe program on 2026-10-25:

| Probe | Result |
|---|---|
| `a = new ulong 2097152 0` in `main` (a 16 MiB local array) | `omc: error 23`. Local arrays are capped at 4 MiB per function, and program-mode stack is 8 MiB (OMEGESE 9.2, 9.4). |
| `global g ulong 2097152`, passed as `f g` to `fn f a edit ulong 2097152` | `omc: error 19`. A global is never passed (OMEGESE 9.4). |
| `global g ulong 2097152`, read and written by name inside a function | Builds. Exits 7, the value it wrote at index 2097151. |
| A 4 MiB local in one function plus 3.2 MiB in its caller | Builds and runs. The cap is per function. |

So no library function can be handed 16 MiB, and no program can build a 16 MiB array except as a
global. The unit is split along that line:

- `argon2.om` is a library unit in the usual form: functions only, no globals, no `main`. It holds
  everything that does not touch the matrix: parameter checks, H0, H', the first blocks, the
  compression G, the Argon2i address blocks, the reference-index computation and the tag.
- `argon2pool.om` is a program-mode companion. It declares the matrix as
  `global a2mem ulong 2097152` (16 MiB), and the read-only salt as `text a2tsalt`. It holds the
  functions that name them: block load and store, the segment loop, `a2hash` and `a2tka`. A program
  includes it once, after `blake2b.om` and `argon2.om`. A future tkad program does the same.

Lanes run one after another, in slice order. Within a slice no lane reads another lane's current
segment (RFC 9106 3.4.1.1), so the result equals the parallel computation. The Go referee runs lanes
in parallel goroutines, and the corpus below matches it.

## Files

| Path | Role |
|---|---|
| `argon2.om` | Library unit, prefix `a2`. Concatenate it after `om/blake2b/blake2b.om`. |
| `argon2pool.om` | Program-mode companion with the 16 MiB matrix. It provides `a2hash` and `a2tka`. |
| `test/driver.om` | Program-mode test driver. |
| `test/trap.om` | Contract-violation program, used by `run.sh`. |
| `test/run.sh` | Test suite. Usage: `sh om/argon2/test/run.sh OMC`. |
| `test/gen/oracle/` | Go referee (`main.go`, `go.mod`, `go.sum`) on golang.org/x/crypto v0.54.0. Test only. |
| `test/gen/vectors.py` | Builds the case list and runs the referee on it. Test only. |
| `test/vectors/rfc9106.txt` | RFC 9106 section 5.2, the Argon2i test vector. |
| `test/vectors/rfc9106.NOTICE` | RFC 9106's Copyright Notice section, verbatim, with a note on what was copied. |
| `test/vectors/go-diff.txt` | 31 parameter sets and 10 TKA secrets, with tags from the Go referee. |
| `test/vectors/reject.txt` | 11 out-of-range parameter sets that must return 1. |

## API

Build order: `cat om/blake2b/blake2b.om om/argon2/argon2.om om/argon2/argon2pool.om main.om | omc`.

```
fn a2hash prm view ulong 8 inp view uchar 65536 out edit uchar 1024 to ulong
fn a2tka sec view uchar 1024 sn ulong o edit uchar 32 to void
```

`a2hash` computes the Argon2i tag:

| Parameter | Meaning |
|---|---|
| `prm` | `[t, m (KiB), p, T, |P|, |S|, |K|, |X|]`. |
| `inp` | `P ‖ S ‖ K ‖ X` back to back, with lengths taken from `prm`. Empty fields are allowed. |
| `out` | Receives the tag in `out[0..T)`. `out[T..1024)` is set to 0. |
| return | 0 on success. 1 if a parameter is out of range, in which case `out` is not written. |

Accepted ranges, checked by `a2setup`:

| Parameter | Range | Source |
|---|---|---|
| t | 1..999999 | RFC: ≥ 1. The upper bound is the unit's loop bound. |
| p | ≥ 1 | RFC. |
| m | 8p..16384 | RFC: ≥ 8p. The upper bound is the matrix capacity. m' = 4p·⌊m/4p⌋. |
| T | 4..1024 | RFC: ≥ 4. The upper bound is the `out` capacity. |

Caller contract, enforced with trap 3 (exit 103): each of |P|, |S|, |K|, |X| is at most 65536, and
their sum is at most 65496. H0's input is 40 bytes of length fields plus the four fields, and it must
fit one 65536-byte `b2bhash` message.

`a2tka` computes the TKA disablement value:

| Parameter | Meaning |
|---|---|
| `sec`, `sn` | The secret. Only `sec[0..sn)` is read. `sn` is 0..1024. If `sn > 1024` the call traps 3. |
| `o` | Receives the 32-byte value `Argon2i(P = secret, S = "tailscale network-lock disablement salt", t = 4, m = 16384, p = 4, T = 32)`. |

Clients generate 32-byte secrets (`cmd/tailscale/cli/tailnet-lock.go:168,178`, v1.102.0). The secret
in a disable request is attacker-controlled, so the request layer must reject a secret longer than
1024 bytes before it calls `a2tka`. A trap would refuse the request, which is a denial of service.
Comparing the result with the stored disablement values is the caller's job.

The matrix is shared by every call, and calls run one after another (Omega has no threads). Each call
overwrites every block it later reads: pass 0 writes all m' blocks before any is read. So nothing
from an earlier call reaches a later result. Blocks past m' keep old contents but are never read.
The matrix is not wiped after a call.

Library functions in `argon2.om`:

| Function | Purpose |
|---|---|
| `a2setup` | Range checks. Fills the state array `st`: t, m', p, q, segment length, pass, slice, lane, T, m, y. |
| `a2h0` | H0 (RFC 9106 3.2 step 1). |
| `a2hp` | H' (3.3). |
| `a2first` | B[l][0] and B[l][1] (3.2 steps 3-4). |
| `a2fm`, `a2gb`, `a2ix`, `a2p` | BlaMka GB and the permutation P on rows and columns (3.6). |
| `a2comp` | G(X, Y), plus the version 0x13 XOR into the old block (3.5, 3.2 step 6). |
| `a2zin`, `a2addr` | The Argon2i address input block and the next address block G(0, G(0, Z)) (3.4.1.2). |
| `a2rlane`, `a2area`, `a2ref` | Reference lane, reference area and the mapping of J1 to a column (3.4.1.1, 3.4.2). |
| `a2tag` | H'^T over the XOR of the last column (3.2 steps 7-8). |
| `a2le32`, `a2cp`, `a2cp64`, `a2b2w` | Byte helpers. |

`argon2pool.om` adds:

| Function | Purpose |
|---|---|
| `a2get`, `a2put` | Load and store a matrix block. |
| `a2i0`, `a2abs`, `a2prev` | Segment start, absolute block number and previous block. |
| `a2blk` | Computes one block. |
| `a2seg` | Runs one segment. |
| `a2init`, `a2fill`, `a2fin` | The phases of `a2hash`. |
| `a2hash`, `a2tka` | The entry points. |

## Standards followed

These are the sections of RFC 9106:

| Section | What it defines | Where the code uses it |
|---|---|---|
| 3.1 | Input ranges | `a2setup`. |
| 3.2 | H0, m', first blocks, passes, final XOR, tag | `a2h0`, `a2setup`, `a2first`, `a2fill`, `a2seg`, `a2blk`, `a2fin`, `a2tag`. Later passes XOR the new block into the old one, which is version 0x13 behaviour. |
| 3.3 | H' | `a2hp`. Takes r = ⌈T/32⌉ − 2 and emits 32-byte prefixes of V1..Vr, then V(r+1) of T − 32r bytes. |
| 3.4.1.2 | Argon2i J1, J2 | `a2zin` and `a2addr`. Z = (r, l, s, m', t, y, counter). A new address block is made at the first index of a segment and at every multiple of 128. |
| 3.4.1.1, 3.4.2 | Reference lane, reference set, J1 mapping | `a2rlane`, `a2area`, `a2ref`. x = J1²/2³², y = (\|R\| · x)/2³², zz = \|R\| − 1 − y, offset by the start of the area. |
| 3.5 | Compression G | `a2comp`. |
| 3.6 | Permutation P and GB, with the BlaMka multiply 2·lo32(a)·lo32(b) | `a2p`, `a2gb`, `a2fm`. Rotations right by 32, 24, 16, 63. Rows are words 16i..16i+15; columns are the 16-byte registers i, i+8, …, i+56. |

The Go referee follows the same steps: golang.org/x/crypto v0.54.0, `argon2/argon2.go`, `deriveKey`,
`indexAlpha` and `phi`.

## Test driver protocol

`driver` reads one case per line from stdin and writes one line per case:

| Input line | Output |
|---|---|
| `T M P TL PW SALT KEY AD` | Decimal t, m, p and tag length, then hex P, S, K and X (`-` for empty). Prints `2*TL` lowercase hex digits, or `e1` when `a2hash` returns 1. |
| `tka SEC` | Hex secret, or `-` for empty. Prints the 64-hex-digit `a2tka` value. |

It exits 0 at end of input and 2 on a malformed line.

`run.sh` does the following:

1. Builds `build/test/argon2/driver`.
2. Checks the RFC vector, the Go corpus and the reject list.
3. If `ARGON2_ORACLE` names a built referee, checks a fresh random Go corpus of `ARGON2_N` cases
   (default 200) from seed `ARGON2_SEED` (default 9106). Without it, that step prints `NOT_RUN`.
4. Runs `trap.om` three times, and each run must exit 103:
   - `a2tka` with `sn = 1025`;
   - `|P| = 65537`;
   - fields that sum to 65497.
5. Runs nine mutants. Each source mutant is rebuilt and run on the RFC vector plus the Go corpus.
   It counts as detected only when the run ended normally (exit 0, one output line per case) and at
   least one tag differs from the expected one. A trap (exit 100+N), a signal, a launch failure or
   short output makes the mutant FAIL. The runs are not piped, so the exit status is kept. The same
   rule applies to the expected-digit mutant. Checked by adding two throwaway mutants and then
   removing them. One trapped on the first case (`if gt s 65496` → `if gt s 0`). The other trapped
   only at the first non-empty `tka` line, after 33 of 42 output lines (`if gt sn 1024` →
   `if gt sn 0`). The suite printed `ran abnormal (exit 103) FAIL` for both and exited 1.

| Mutant | Change |
|---|---|
| expected digit | One flipped expected digit. |
| version | Version 0x13 → 0x10 in H0. |
| type | Type y = 1 → 2 in H0. |
| blamka | BlaMka multiply dropped (plain addition). |
| column | Column permutation replaced by row indexing. |
| area | Reference area not reduced by 1. |
| counter | Address counter not incremented. |
| xor13 | No XOR into the old block in later passes (the version 0x10 rule). |
| addr128 | No new address block at index multiples of 128. |

## Vector sources

**RFC 9106 section 5.2 (Argon2i).** From https://www.rfc-editor.org/rfc/rfc9106.txt, fetched
2026-10-25. The file's sha256 is `855c06f060379e34285e83a217e9069b5c72e161a1e54df9af5cd88dbb231f31`.
Parameters: t=3, m=32, p=4, T=32, P = 32 × 01, S = 16 × 02, K = 8 × 03, X = 12 × 04.
Tag: `c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8`.

**Go corpus (`go-diff.txt`).** Generated by `python3 test/gen/vectors.py ORACLE` from seed 9106.
Generating it again with the same referee gives identical bytes; this was checked with `cmp`. The
referee is `test/gen/oracle`, built with go1.26.0 linux/arm64 against golang.org/x/crypto v0.54.0.
tailscale.com v1.102.0 pins that same version in its `go.mod`.

- Lines with K = X = empty call the public `argon2.Key`.
- Lines with K or X call the package's internal `deriveKey`, the function `Key` wraps, through
  `go:linkname`, because the public API has no K or X. On every line with K = X = empty, the referee
  also checks that `argon2.Key` and `deriveKey` agree.

The 31 parameter sets:

| Cases | What they cover |
|---|---|
| m=8, p=1 | The smallest memory. |
| Empty password | |
| RFC shape with random bytes | |
| m = 37, 63, 100 | m not a multiple of 4p. |
| p = 3, 5, 8, 16 | |
| m = 512, 1024, 1536, 2048, 4096 | Segments of 128, 256 and 1024 blocks, which need one to eight address blocks. |
| T = 4, 5, 63, 64, 65, 96, 100, 128, 129, 512, 1024 | Both sides of every H' branch. |
| Long fields | P = 4000 and X = 4000, and P + S at the 65496-byte H0 capacity. |
| m = 16384 with p = 1 and p = 4, and m = 16383 with p = 4 | The full 16 MiB matrix. |
| t=4, m=16384, p=4, T=32 | The TKA cost parameters with a random salt. |

The 10 `tka` lines use secrets of 0, 1, 16, 32 (×4), 33, 64 and 1024 bytes.

**Reject list (`reject.txt`).** Hand-written from the RFC 3.1 ranges and this unit's limits:

| Case | Value |
|---|---|
| t | 0, 1000000 |
| p | 0, 2049 |
| m | 31 with p = 4, 7 with p = 1, 16385, 9999999 |
| T | 0, 3, 1025 |

To regenerate:

```
cd om/argon2/test/gen/oracle && go build -o /tmp/argon2-oracle .
python3 om/argon2/test/gen/vectors.py /tmp/argon2-oracle > om/argon2/test/vectors/go-diff.txt
```

## Third-party material and notices

| Copied material | Owner and terms | Notice file |
|---|---|---|
| Parameters, inputs and tag of RFC 9106 section 5.2, in `vectors/rfc9106.txt` | Copyright (c) 2021 IETF Trust and the persons identified as the document authors. RFC 9106 is an IRTF stream RFC (Crypto Forum Research Group), subject to BCP 78 and the IETF Trust Legal Provisions. | `vectors/rfc9106.NOTICE`: the RFC's Copyright Notice section, verbatim (sha256 `8704dbca8266c2115313362127842fa324523027c10a862dd1d754828537606a`). |

The RFC 9106 notice is included for attribution only. Its boilerplate grants no code-component
licence. Section 4 of the IETF Trust Legal Provisions (TLP 5.0) is the section that licenses code
components. TLP 5.0 §8(g) says it does not apply to IRTF stream documents; this was checked against
https://trustee.ietf.org/wp-content/uploads/Corrected-TLP-5.0-legal-provsions.pdf, fetched
2026-10-25, sha256 `b5cbd993d1dae273d7b251db4efc397b4de13451b2156b94d5a901c83c0fb48a`. Whether the
copied test values count as code components, and whether attribution is sufficient, has not been
determined.

Not copied:

- The tags in `go-diff.txt` are outputs of the Go referee, not text taken from any source.
- `gen/oracle/main.go` calls golang.org/x/crypto (BSD 3-clause) as a module dependency. It vendors
  none of its source; it only declares the `deriveKey` signature for `go:linkname`.
- The Omega code was written for this unit and contains no copied source text. Go's sources are
  cited by file and function name only.
- The salt `"tailscale network-lock disablement salt"` in `argon2pool.om` is the 39-byte constant
  from tailscale.com `tka/state.go:116`, reproduced because interoperability requires it.

## Evidence (2026-10-25, linux arm64 host)

```
$ ARGON2_ORACLE=<built test/gen/oracle> sh om/argon2/test/run.sh "$(tools/omc.sh)"
argon2: omc sha256 734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61
argon2: driver sha256 00da3121dc5c5368fa5a040c75747326fb7543a3bd22c6deeb7aa0e6cd0d93f4
argon2: rfc9106 1/1 PASS
argon2: go-diff 41/41 PASS
argon2: go-diff has 31 parameter sets and 10 tka secrets
argon2: reject 11/11 PASS
argon2: random seed 9106
argon2: random 200/200 PASS
argon2: trap 1 exit 103 PASS
argon2: trap 2 exit 103 PASS
argon2: trap 3 exit 103 PASS
argon2: mutant expected-digit detected PASS
argon2: mutant version detected PASS
argon2: mutant type detected PASS
argon2: mutant blamka detected PASS
argon2: mutant column detected PASS
argon2: mutant area detected PASS
argon2: mutant counter detected PASS
argon2: mutant xor13 detected PASS
argon2: mutant addr128 detected PASS
```

The run exited 0 in about 31 s. Most of that time is the eight source mutants, each of which runs
the whole RFC vector and Go corpus to completion. Other runs:

| Run | Result |
|---|---|
| Random seeds 1, 2 and 3 with `ARGON2_N=500` | 500/500 each. |
| Without `ARGON2_ORACLE` | The random step prints NOT_RUN, everything else passes, exit 0. |

**Runtime of one TKA disablement evaluation**, measured with `/usr/bin/time` on this host:

| Command | Wall time | Max RSS |
|---|---|---|
| `driver <<< "tka 0011…eeff"`, 5 runs | 0.25 to 0.27 s | 16.5 MiB |
| 10 `tka` lines in one process | 2.54 s, about 0.25 s each | |
| Go referee, same 10 lines, `GOMAXPROCS=1` | 0.38 s | |
| Go referee, same 10 lines, default `GOMAXPROCS` | 0.19 s | |

Hashes:

| Item | Value |
|---|---|
| omega-mv pin | `acb3f15cdc691b1b046b48b0dad0f9255a12ba4b` |
| omc sha256 | `734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61` |
| `argon2.om` sha256 | `bf1984ec4735fac106ca3e5f08ddeab6b1dc3826780f93a532794e5ef46189ec` |
| `argon2pool.om` sha256 | `247617c3055ad8fae77871d2a761cba69aa1c0c386596dc70bc0bed1aaca3ce1` |
| `test/driver.om` sha256 | `3a652fd707248bdf9eddd20fedcbacc85a8337d4af717ef7648aa87ade57aeb8` |
| driver binary sha256 (with `blake2b.om` `91299627…42fd`) | `00da3121dc5c5368fa5a040c75747326fb7543a3bd22c6deeb7aa0e6cd0d93f4` |

These are host runs only. They are not hardware qualification.

## Limits

- **Not constant-time-audited.** Omega gives no timing guarantee, and no timing side channel was
  measured. Argon2i's memory access pattern does not depend on the password, by design
  (RFC 9106 3.4.1.2). The code was not audited for data-dependent branches.
- Argon2i only. There is no Argon2d or Argon2id.
- m is at most 16384 KiB, which is the matrix capacity. T is at most 1024. t is at most 999999. The
  four inputs together are at most 65496 bytes.
- `argon2pool.om` declares a global, so it works only in program mode, once per program. Calls must
  not overlap. Omega has no threads, so they cannot.
- The matrix is not wiped after a call. Its contents, derived from the secret, stay in process memory
  until the next call overwrites them.
- Lanes are computed one after another. There is no parallel speed-up.
