# Bounded Tailnet Key Authority

Omega implementation of the typed AUM, Key, State and AUM Signature models, signature authorization,
state transitions, and an in-memory authority DAG. Behavior is pinned to
[Tailscale v1.102.0](https://github.com/tailscale/tailscale/tree/v1.102.0/tka), particularly `aum.go`,
`key.go`, `state.go`, `tka.go`, and `sync.go`. No production Go code or node-key-signature implementation
is included here. Node-key signatures belong to `om/tkasig`.

## Composition

Concatenate `om/blake2s/blake2s.om`, `om/sha512/sha512.om`, `om/ed25519/ed25519.om`,
`om/cbor/cbor.om`, `tka.om`, `tkastate.om`, and, for the authority API, `tkapool.om`, before the caller.
The first two TKA files are global-free functions. Include the pool companion only once.
There is no filesystem, daemon, persistence, compaction, network configuration, or concurrency in
this unit. Callers serialize pool access and persist a successful transaction before publishing it.

## Model API

Unless stated otherwise, byte buffers have capacity 65536 and lengths are `ulong`.
Lengths 0–65536 are successful; errors are 65537 (typed CBOR), 65538 (resource limit),
65539 (static validation), 65540 (signature), 65541 (parent/key/state), 65542 (not initialized,
transaction misuse, or no sync intersection). Success/error must be checked before consuming output.

* `tkamodel(input,n,schema,out,keep)` decodes a complete typed object and reconstructs its encoding.
  Schemas: 1 AUM, 2 Key, 3 State, 4 AUM signature. `keep=0` gives canonical serialization;
  `keep=1` is an internal typed representation retaining empty-but-non-nil optional values.
  In particular an empty metadata map is not interchangeable with nil during UpdateKey validation.
  The output is unchanged on failure. Input and output must be distinct arrays.
* `tkadec(input,n,out)` is canonical AUM reconstruction. Unknown fields are checked for CBOR
  well-formedness then dropped; non-shortest encodings, reordered maps, decimal field-name text keys,
  and integer arrays for byte slices are accepted as upstream accepts them. Duplicates and typed
  errors reject. Hashing never uses received bytes directly.
* `tkahash(input,n,sig,out32)` returns 0 or an error. `sig=0` computes AUM Hash, `sig=1` SigHash.
* `tkavalid(input,n)` returns 0 or an error for upstream StaticValidate, separate from authorization.
  Unknown AUM kinds are valid forward-compatible no-ops, not an unsupported-version error.
* `tkatrans(aum,n,state,sn,out,genesis)` verifies and applies to a typed State, returning its new
  encoded length. `genesis=1` is only for bootstrap, and skips parent matching. On failure the caller
  must discard `out`; the input state is never changed. All signatures must name trusted keys and
  verify under ZIP-215, even when another signature is valid. Duplicate signatures are valid but
  count once for fork weight. The last key cannot be removed. Checkpoints preserve both StateIDs.

Internal token helpers require a successfully normalized model and successful `cbrdec`; they are
not hostile-byte entry points. Public lengths are checked before CBOR or cryptographic calls.
The cryptographic implementation is variable-time and has not been constant-time audited.

## Authority API

Two independent authority slots permit bounded in-process synchronization. `tkaselect(slot)` selects
0 or 1 (returns 0 or resource error). `tkareset()` explicitly clears the selected slot. A slot holds
128 immutable AUM nodes, each with up to 65536 encoded AUM bytes and 65536 state bytes. The two slots
reserve approximately 32 MiB plus metadata globally; fixed-size per-operation scratch lives on the
Omega stack. State keys are bounded at 512 (including AddKey), disablement values at 32, and key
metadata at 512 UTF-8 bytes. Input CBOR retains its existing depth16/array4096/map1024 limits.
These are resource errors where tighter than upstream; no eviction or hidden history truncation occurs.

* `tkaboot(input,n)` accepts a signed checkpoint into an empty authority, returning 0 or error.
  Later checkpoints with a non-nil parent may bootstrap, just as upstream permits.
* `tkainform(input,spans,count)` accepts a batch atomically. `spans` is `ulong[256]`, alternating
  offset,length for at most128 messages in one input buffer. Parents precede children. On any error,
  the visible node count, head, states and key table remain unchanged. Already-stored canonical hashes
  are idempotent and skip static/signature revalidation, matching upstream.
* For a batch larger than one input buffer, `tkabegin()`, successive `tkastage(input,n)`, and
  `tkacommit()` provide the same transaction. A failed stage automatically aborts the entire batch;
  explicit `tkaabort()` is also available. The caller must not query or interleave other operations
  while staging.
* `tkahead(out32)` returns 0 or error. `tkacurrent(out)` and `tkastate(hash32,out)` return the encoded
  current state or a state at any retained branch node; canonicalize with schema3 for wire output.
* `tkakeys(out16384)` returns the count of concatenated 32-byte Ed25519 public keys, or error.
  This is the trusted-key table for `nksauth`; regenerate after a committed head change. Keys with
  malformed public lengths (which upstream static validation allows) cannot authorize signatures
  and are not exported.
* `tkaoffer(out)` writes head followed by ancestor hashes and returns the total hash count.
  Samples occur at absolute depths4,16,64; oldest is appended unconditionally, including an oldest
  already sampled at an exact sampling boundary. A 128-node DAG cannot reach the next sample256.
* `tkainter(offer,count,mode1)` returns the intersecting node index or error. `mode1[0]` is0 for
  up-to-date,1 for head intersection,2 for tail intersection. Offers contain at most2048 hashes.
* `tkamissing(offer,count,nodes128)` returns a count of ordered local node indices. Fetch each AUM
  using `tkaget(index,0,out)`, then canonicalize with schema1 for transport. Only the chosen primary
  continuation is sent, not every off-chain branch. An equal head returns no updates.

The fork rule is highest unique signer vote sum, then RemoveKey over non-RemoveKey, then lowest
canonical AUM hash bytewise. Cached state at every node makes arbitrary retained-branch state lookup
bounded, and avoids replay during signature verification. A checkpoint can replace keys and disablement
values but cannot change the authority IDs.

## Tests

Run `TKA_GO=/path/to/go1.26.8 sh om/tka/test/run.sh /path/to/pinned/omc` from the repository.
`tools/omc.sh` supplies the pinned compiler when omitted. Requirements: ARM64 Linux, Python3,
POSIX shell, Go>=1.26.5, and dependencies pinned in `test/oracle/go.mod` and `go.sum`.

The Go oracle imports the real pinned `tailscale.com/tka` and emits deterministic commands and expected
records. The Omega driver executes those same commands. Scenarios cover bootstrap and later-checkpoint
bootstrap, add/update/remove/checkpoint, state lookup, StateID rejection, unknown kinds, untrusted and
invalid signatures, unknown parents, batch rollback, duplicates, vote and hash fork ties, last-key
removal, sync intersections, exact ancestor sampling boundaries, and convergence. Explicit bounded-profile
cases check 128-node exhaustion, capacity-failure rollback, and rejection of a 513th key. Existing CBOR
structure/hostile/fuzz AUM and State corpora are re-judged through the typed model (not merely generic
CBOR well-formedness). A signature-verification mutant must run to normal completion with the same
record count and at least one changed result; traps, signals, or an incomplete run fail the harness.
The focused suite was executed with Go1.26.8 and the pinned compiler: **PASS, 10,691 differential
records**, and the signature mutant completed all 10,691 records with four differences. The separate
cross-unit revocation driver also completed successfully: a direct node signature authorizes after
bootstrap and rejects after its trusted key is removed by a signed AUM.

`test/revocation.om` is compiled with both authority and node-signature units by the harness.
The oracle's `--fixture` mode emits JSON with hex `genesis`, `removal`, `signature`, and raw32-byte
`node` fields. It constructs the signed pubkey through upstream NodePublic.MarshalBinary (including
the `np` prefix) and asserts upstream authorization before, and rejection after, revocation.
For standalone use: run `go run -mod=readonly . --fixture` in `test/oracle`.

Fixed-array hash decoding follows upstream padding/truncation semantics, while byte slices preserve
nil versus empty for serialization. Static key-ID equality follows Go bytes.Equal, which treats nil
and empty as equal; these semantics have dedicated typed-model cases.
An empty-but-present update metadata map is exercised through explicit wire bytes: it clears
metadata, then replay of its canonically omitted form is accepted by the already-stored hash without
revalidating the now-missing update field.
The corpus also exercises all 256 simple-number encodings in seven typed destinations. As upstream
fxamacker `fillPositiveInt` specifies, major7 simple values with additional-information0–19 or24
populate unsigned fields and byte-array elements; Boolean values remain type errors, and null or
undefined leave zero values.

### Third-party material and notices

Protocol behavior and translated algorithms derive from Tailscale v1.102.0, commit
`35283c95445fb198af1ce708dac05714bdfaa037`, fetched2026-10-25. Copyright Tailscale Inc & contributors,
BSD-3-Clause; the upstream notice is shipped verbatim in `tailscale.LICENSE`. The Go decoder options
are transcribed from `tka/tka.go` and covered by that notice. Other Go code is only an external test
oracle. Shared CBOR vectors retain their provenance and notices in `om/cbor`.
