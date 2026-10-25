# SC1-Q durable framing charges

Base: `security/3-consumer-enforcement` at `b571465`, which supplies `om/quantity`.
This slice is the WORM-owned durable-state side of the SC1-Q row and touches no
transport, revision or comparison function owned elsewhere.

## What changed

`om/store/storepool.om` now charges a record against the store limits with the checked
quantity operations instead of loose integer comparisons:

| Function | Admitted effect |
|---|---|
| `stbound` | a record length is admitted only inside the fixed 65536 frame buffer |
| `stcharge` | running byte total accumulated with `qadd` up to the 33554432 cap |
| `stcount` | running record count accumulated with `qnext` up to the 65536 cap |
| `stwrite` | one charge of length, total and count before any header, payload or footer write |
| `stnext` | the same three charges before a record is accepted while reading |

The refusal codes are unchanged (`stwrite` 1 with the poisoned flag, `stnext` -1), so every
existing caller and test keeps its contract. Two differences are deliberate:

- A charge of `n = 65537` and a total over cap now refuse through the same path instead of
  two hand-written comparisons, so a future caller cannot re-derive one and forget the other.
- A running charge below zero is a declared refusal. The previous form cast the counter to
  `ulong` directly, which is a checked conversion in Omega and traps; it is not a reachable
  store state, but a trap in the middle of a write is a worse answer than a refusal.

## Audit of the neighbouring producers, no source change

Record lengths and counts that reach `stwrite` were traced to their producers before deciding
not to change them:

- `cmd/tkad/state.om` `dssave` passes `dsget 3`, `dsget 4`, `dssig` and `tkaget` lengths. All of
  them are now bounded at the single effect boundary, so a bounded length in `dssave` is
  admitted or refused by the same charge and cannot be forgotten there.
- `cmd/tkad/socket.om` takes `ds_ctl 3` from header byte 5 (`gt get h 5 1` refuses anything but
  0/1) and `ds_ctl 4` from header byte 4, a single byte, so the `dsget 3`/`dsget 4` loops in
  `dssave` cannot exceed 1 or 255 against a 65536 buffer.
- The disablement secret reaches `dssecretput` only through `dsvalidsecretat` (`gt n 1024`
  refuses) and `dsdisable` (`gt n 1024` refuses), matching `om/argon2` `a2tka`, and
  `ds_sup`/`ds_dis` are 2048 bytes with a 1024 stride. The two copy sites are bounded at both
  ingresses.

No vulnerability is claimed or retracted by this audit: the values were already bounded, and
the inventory note "absence of migration is not evidence of a bug" still applies to every
module this slice did not touch.

## Controls

`om/store/test/run.py` already pins the reachable caps: `U` (one 65537 chunk refused), `Q`
(exactly 65536 frames, then refuse one more) and `C` (exactly 32 MiB, then refuse one more
byte), each asserting the committed snapshot is byte-identical afterwards. This slice adds the
two charge refusals that are not reachable from the public API:

- `Y` sets a negative running byte charge in the test image and requires a declared refusal.
- `B` sets a negative running record count and requires a declared refusal.

Both run on the same image that serves the rest of the suite, and both restore-verify the
committed snapshot.

Mutants are deliberately not claimed for these two controls. A mutant that drops the checked
step differs from the original only in a state the public API cannot reach, and the difference
it produces there is a trap, which the mutant rule in issue #3 says is not detection. The
reachable-cap controls `U`/`Q`/`C` remain the behavioural pins for the caps themselves.

## Reproduction

```sh
sh om/store/test/run.sh
sh cmd/tkad/test/run.sh
sh tools/test.sh
```

Verdict at this head: `PASS store` (118 native cases), `PASS tkad` (224 assertions plus the
disk-full, restart, self-exec and corruption arms), `PASS quantity`, `PASS tkasig`, and the
crypto unit suites, from `sh tools/test.sh` (`127` PASS lines, exit 1). The two `FAIL` lines are
`json` and `tka`, and both stop on `go: not found` while building a Go oracle or running the
Go TKA oracle on this host, which has no Go toolchain. This slice touches neither unit, so
those two rows are environmental here and carry no verdict on this change.

The store suite compiles `om/quantity`, `om/blake2s`, `om/store` and the store pool together,
then runs the driver natively; the daemon suite exercises the same store through the real
socket protocol, including disk-full, restart and corruption cases.

## Not claimed

- `cmd/tkad/state.om`, `cmd/tkad/rpc.om`, `cmd/tkad/helpers.om` and `cmd/tkad/main.om` remain
  outside the admitted quantity subgraph.
- No constant-time, secrecy, power-loss or whole-path claim is made here.
- The standing per-slot and temporary-reserve charges for the R5 durable resource frame are not
  implemented by this slice; these helpers are the accounting primitives that work starts from.
