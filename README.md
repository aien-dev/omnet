# omnet

Security-critical network code, rewritten in [Omega](https://github.com/aien-dev/omega-mv).

Most serious vulnerabilities in network software over the last several decades come from a short list
of bug classes: out-of-bounds reads and writes, integer overflow, unbounded reads and loops,
use-after-free, and check-then-use races. omnet rewrites security-critical parts of network
infrastructure in a language where the first group cannot happen silently. Its design rules target
the rest.

The first project is **Tailnet Lock for self-hosted Tailscale control servers**. Tailnet Lock (TKA)
lets the devices of a tailnet, not the control server, decide which devices may join. The stock
Tailscale client already implements the device side. The open-source control server
[headscale](https://github.com/juanfont/headscale) does not implement the server side
([headscale#1307](https://github.com/juanfont/headscale/issues/1307)). omnet builds that server-side
logic in Omega.

## What the language rules out, and what it does not

Facts below are from the Omega language reference, `docs/one_layer/OMEGESE.md` §9, at the pinned
commit in [`omega.pin`](omega.pin).

| Bug class | Omega behaviour |
|---|---|
| Out-of-bounds array access | Every index that is not a constant is checked when it runs: trap 3. Constant indices outside the array are refused at compile time. Kernel I/O checks its buffer range before the call. |
| Signed integer overflow | Signed `add sub mul neg div shl` trap 1 when the exact result does not fit. |
| Lossy conversion | A conversion to a type that cannot hold the value traps 5. There are no implicit conversions. |
| Bad shifts, division by zero | A shift outside `0 .. width-1` traps 7; division by zero traps 2. |
| Unbounded loops | Every loop has a bound (default 1,000,000 passes); passing it traps 4. |
| Heap corruption, use-after-free | There is no heap allocator and no exposed pointer. Arrays have a fixed length that travels with the name. Local arrays are freed under compile-time ownership checks. |
| Stack exhaustion | A call or local array that would overrun the fixed 8 MiB stack traps 6 before writing. |

A trap stops the program. That turns memory corruption into a crash, so a reachable trap is still a
denial-of-service bug.

**Not ruled out by the language**, and therefore handled by review and by the design rules below:

- Logic and protocol errors, including wrong authorization decisions.
- Unsigned arithmetic, which wraps by definition. Cryptography relies on that, and it can still hide
  a length bug.
- Timing side channels. omnet code is **not** constant-time-audited.
- Races on file-system paths (time-of-check to time-of-use).
- Resource exhaustion at the service level: too many clients or too much stored state.

## Design rules for omnet code

1. **Bounded input.** Every read has an explicit capacity, and every message has a maximum size that
   is checked before it is parsed.
2. **No check-then-use on names.** Act on an opened descriptor, never on a path checked earlier.
3. **Fail closed.** A parse error, signature failure, or unknown field version means reject, never
   skip.
4. **Least privilege.** A component that parses untrusted input runs without the privileges of the
   component that acts on the result.
5. **Two referees.** Each algorithm is checked against published test vectors and against an
   independent implementation used only as a test oracle (never shipped). Every test harness has a
   mutant check that proves it can fail.

## Layout

| Path | Content |
|---|---|
| `om/<unit>/<unit>.om` | Omega library: functions only, no globals, no `main` |
| `om/<unit>/test/` | Program-mode test driver, vectors, `run.sh` |
| `docs/design/` | Design documents |
| `tools/omc.sh` | Builds the pinned seed-born Omega compiler and verifies its digest |
| `tools/test.sh` | Runs every unit's tests |

## Build and test

Requirements: Linux on ARM64 (the Omega compiler emits AArch64 Linux programs), `git`, POSIX `sh`.
Python 3 is optional and is used only to generate differential test data.

```sh
tools/test.sh      # builds the pinned compiler on first use, then runs every unit's tests
```

## Status

Pre-alpha. See [`docs/design/tailnet-lock.md`](docs/design/tailnet-lock.md) for the plan and the
current state of each part.

## License

Apache-2.0. See [LICENSE](LICENSE).
