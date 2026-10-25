# SC1 actual consumer changes

Based on omnet PR#4 at `1e075776855d4389b69b23b54b49ed230d488717`.
This is a proposal for the existing WORM-owned daemon, not a new service or store.

## Implemented changes

- `socket.om`: original frame length, remaining byte count, positive syscall result
  and cursor advancement use the imported checked quantity operations before effects.
  The original u32 frame decoder was already bounded; no prior wrap exploit is claimed.
- `adapter.om`: `dsadvance` uses checked `qnext` for candidate snapshot Revision
  before `dssave`. Existing maximum409 refusal and publish/error ordering are preserved.
  Revision is not a generic policy epoch.
- `rpc.om`: successful empty/already-retained AUM sends do not mark the candidate
  dirty. Retained count is monotonic; identical immutable nodes imply deterministic
  identical head/state. New losing-fork nodes still count as changes. Interactive
  resulting-head verification and upstream canonical-replay acceptance are unchanged.
- `helpers.om`: compare all32 hash bytes, and accumulate across the complete public
  candidate list. Source no longer returns at the first mismatch or matching index.
  Public request length/candidate shape and final authorized validity are explicit.

`quantities.json` binds the admitted transport/revision subgraph and all remaining
production modules/functions. It does not declare unreviewed arithmetic safe or
vulnerable. Intentional crypto wrapping is unchanged. All runtime source changes
are `.om`; the existing build list adds the quantity source.

## Reproduction and evidence

The existing `tools/test.sh` discovers `om/quantity/test/run.sh`. That file is only
bootstrap glue: it reconstructs the pinned compiler, builds and execs the existing
`qualification/security3/run.om` coordinator with `--consumer-units`. Every new
case-selection, composition, mutation, status/output assertion and verdict is .om.
The coordinator uses the actual production build output, verifies/removes its exact
main suffix, and appends fixture main functions. It never copies the positive
transport/comparison implementation into a test.

```sh
sh om/quantity/test/run.sh
sh tools/test.sh
```

Native unit expectations: runtime quantity/demo and crypto0; four mixed types
compile7 (never execute); actual consumer fixture0; secret modes0/1/2 execute0,
constant-valid mutant3 executes12. The byte/list early-return controls intentionally
pass ordinary functional tests; this demonstrates why those tests are insufficient.
Add/mul/cursor/no-op source mutants must compile and normally exit1 with their named
failure marker. An unrelated trap or failed compile is not a detected mutant.

`native.json` records the initial actual-source tests and two consumer controls.
It predates `dsadvance`; its exact source/binary hashes remain historical, not
current. Final clean-source results must bind the changed concatenation separately.
The real socket/append/restart/fault/disclosure/benchmark coordinator and raw results
are in `../security3/`; its baseline and candidate hashes distinguish their scopes.

## Native secrecy evidence, not a whole-path claim

The exact function-mode `dseqhash` source compiles to96 bytes. The pinned #752
scanner reports zero DATA branches/addresses, zero unknown/unhandled and PASS.
The old first-mismatch control has one DATA branch and NOT_RUN. Both compiled
controls execute normally in the functional suite. This is architectural static
primitive evidence, not measured constant-time behavior.

The entire96-byte function-mode artifact does NOT occur byte-for-byte in the
program-mode daemon. `scanner.json` records zero matches: emitted correspondence
is BLOCKED pending the existing #623 relation; no slice of code is silently omitted.
`dssecretmatch` plus the real CBOR dependency scans NOT_RUN (public scratch/pointer
provenance is conservatively lost; zero unknown/unhandled). The early-list control
also scans NOT_RUN. That result is neither proof of a remaining leak nor secrecy.
Full scans and artifact hashes are retained in `*.scan` and `list-scanner.json`.

The full secret closure remains unqualified: raw JSON/base64, Argon2i/BLAKE2b,
state copies, snapshot BLAKE2s/framing/writes, recovery checking, stack/pool reuse,
stale-temp cleanup and crash dumps. At rest the secret is plaintext under the
private-directory/same-UID policy. No zeroization/remanence, cache, speculation,
instruction-latency, OS-scheduling or physical-secrecy claim is made.

## Explicit owner dependencies

- Current IPC trusts same-UID adapter assertions; real remote-principal authentication
  requires the existing Headscale/Noise owner. Signature checking is separately real.
- Current snapshot has no durable aggregate budget/envelope/fuel frame. WORM must
  choose derived accounting with standing temporary reservations or a versioned
  schema/migration, inside its existing writer, not a second ledger.
- Current serial dispatch exposes completion time; the existing scheduler owner must
  enforce public admission/release envelopes. Pure helper/model equality is not that.
- Generic operation-ID/epoch/version request fencing is not IPCv1. TKA signatures
  follow parent-state validity and fork choice, not a replacement current-head policy.
- Existing process-crash/fault variants do not qualify power loss or Linux writeback
  EIO recovery. Same-UID/root hostility and cross-namespace writers remain outside profile.

Independent source review found the production changes correct. That review is not
policy approval, remote authentication, complete native secrecy or deployment approval.

## Final clean-checkout replay

`clean-service-replay.json` binds consumer `6e0fff2` (candidate source
`b65bf2f8…`, binary `e2770128…`) and the independently pinned base `1e075776`
(source `5a85c0e6…`, binary `c0869a7f…`), compiler `734f0a39…`, contract
`ced61dec…`. From fresh worktrees:

- `tools/test.sh` exit0: all library suites, `--consumer-units` (type refusals
  compile7, four production mutants normal exit1 at named markers) and224 real
  socket assertions. NOT_RUN: random Argon2 oracle corpus, CBOR oracle
  regeneration. SKIP: foreign-UID chown fixtures (non-root runner).
- Default socket mode from the base checkout against the candidate: exit0,
  including restart, short-write, ENOSPC, post-rename uncertainty (74), wrong-count
  control (41/202) and checksum-valid support-secret omission (41/243).
- `--candidate-faults` with the candidate hashes: exit0, same fault arms bound to
  candidate-derived executables.
- Canonical no-op replay: base Revision5→6, candidate5→5 (A9 suppression).

Matched route p50 (two batches): map ~0.27–0.30 ms both arms; canonical replay
8.0–8.4 ms base versus0.63–0.67 ms candidate because the rewrite is removed. VmHWM
23,512 vs23,516 KiB. Baseline ran before candidate on a shared host: regression
evidence only, no SLA or timing-secrecy claim. All11 persisted snapshots are kept
as base64 with SHA-256.

`clean-scanner-replay.json` rebinds the bounded function-mode scans to the final
source: `dseqhash` 96 bytes PASS, `ssfirstbyte` NOT_RUN (one DATA branch), list
match plus CBOR dependency NOT_RUN for both the candidate and the early-list
control. No whole function occurs byte-for-byte in the daemon; L6/L7 stay BLOCKED.
