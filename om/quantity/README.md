# Checked quantities (SC1-Q)

Apache-2.0 source imported byte-for-byte from Omega's `om/quantity/` proposal
[#771](https://github.com/aien-dev/omega-mv/pull/771), not a second implementation.
The `q` function prefix names this unit. Compiler pin is unchanged.

`qty {val,cap}` distinguishes bounded quantities from modular scalar words;
`qobj {ident,ver,extent}` and `qslic {ident,ver,off,count}` bind a view to an
owner-assigned nonreused object/version, not an fd number. Raw fields remain
trusted construction boundaries, not sealed capabilities or physical units.

All calls return int:0 success,1 malformed input,2 domain mismatch/negative signed
ingress/widening through narrow,3 overflow/underflow,4 object mismatch. Refusal
leaves output unchanged. Output/input structs must be distinct (seed alias rule).

- `qword`, `qsigned`: validate original ingress before conversion/effects.
- `qadd`, `qsub`, `qmul`: validate both inputs/equal caps before guarded arithmetic.
- `qnarrow`: target cap cannot exceed source cap; value must fit.
- `qnext`: refuse cap exhaustion; no wrapping policy epoch.
- `qtyslice`: validate expected/current identity, version, extent, then offset and
  count by subtraction before address formation.

A constructor applied after a wrapped sum cannot recover the original operands.
Revalidate serialized slices from original offset/count against the trusted current
object immediately before effects. Same caps do not distinguish application units.

Actual consumer: `dsframe` and `dsio` validate decoded lengths and cursor arithmetic
before socket effects; `dsgrow` checks positive signed syscall results before
conversion and checked addition. `dsbound` rechecks final response length, but it
cannot prove that all upstream response-writer arithmetic was checked. The remaining
producer/effect inventory is in `qualification/security3-consumer/quantities.json`.

## Qualification

The imported runtime fixtures cover widths1..8, u64 wrapping products, negative
input, narrowing, object/version mismatches, unchanged refusal outputs and epoch
exhaustion. Four mixed nominal fixtures must compile-refuse7; crypto wrapping
must execute0. The exact-source add/mul guard mutants must compile and normally
fail their named assertions. `oracle-export.om` emits262140 actual records for
external exact-arithmetic comparison; raw corpus evidence lives in Omega #771.
These are finite/native tests, not a language-wide or translation theorem.

`sh om/quantity/test/run.sh` is registered by the existing `tools/test.sh` glob.
It only bootstraps the pinned compiler and executes the existing security3 `.om`
coordinator. All selection, source composition, mutation, exit/output checks and
verdicts are in `qualification/security3/run.om --consumer-units`, not shell.
That mode also exercises actual transport/no-op and secret-comparison fixtures;
see `qualification/security3/README.md` for exact commands and retained results.

## Third-party material and notices

No third-party algorithm or vector text is copied into this unit. Omega source is
Apache-2.0, the same license as omnet. Imported deterministic fixtures are synthetic.
The independent arbitrary-precision arithmetic oracle is a development tool, not
shipped production/test-runner logic.
