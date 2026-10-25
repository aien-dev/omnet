# tkad: bounded local Tailnet Lock service

Production code is Omega, compiled by `tools/build-tkad.sh` with `tools/omc.sh`.
Go and Python under `test/` are test-only. Protocol types are pinned to Tailscale
v1.102.0 `tailcfg/tka.go` and `ipn/ipnlocal/tailnet-lock.go`.

## Invocation and trust boundary

Provision an empty directory owned by the effective UID, mode0700, under a trusted
ancestor chain. Run `build/tkad /absolute/state/directory --init` exactly once.
Subsequent starts use `build/tkad /absolute/state/directory`. Missing or corrupt
snapshots refuse startup; initialization refuses an existing snapshot.

The service creates `tkad.sock` inside its opened directory, mode0600. The
0700directory and0600socket enforce a same-UID/root **trusted local adapter**
boundary. There is no SO_PEERCRED operation in the pinned native ABI and no claim
of peer-credential inspection. Same-UID/root processes can act as the adapter,
read secrets and change storage. This is not Noise authentication, HTTP serving,
a deployed Headscale integration, or a distinct-UID privilege boundary. The
adapter must authenticate remote clients and derive node IDs/admin assertions
from its trusted identity model, never from remote JSON.

A descriptor-held abstract AF_UNIX bind lock, derived from directory device and
inode, admits one writer. All writers must use the same network namespace. Only
a lock holder removes the reserved stale socket pathname. No PID-file or
connect-failure lock inference is used. A process crash leaves a pathname that a
new lock holder can remove safely.

## IPC version1

One request and one response per AF_UNIX stream connection. Integers are unsigned
little endian. Header fields must be complete; there is no implicit terminator.

Request header,20bytes:

| Offset | Size | Meaning |
|---|---|---|
|0|4|Bytes `54 4b 41 01` (`TKA` and version1)|
|4|1|Route ID below|
|5|1|Trusted adapter admin assertion, exactly0 or1|
|6|2|Reserved, zero|
|8|8|Authenticated NodeID; RPCs require a registered positive signed64-bit ID|
|16|4|Raw JSON byte length,0..65536|

The body is the unmodified upstream JSON request. Response header,12bytes, has
the same magic at0, HTTP-style status as u16at4, reserved zero u16at6, and JSON
length u32at8. A200body follows the exact upstream response field shapes. Errors
have a short fixed JSON body, never request details or secrets. Bad/truncated
headers and oversized payload declarations close that connection without a reply.
Each receive/send phase has an absolute3second deadline, nonblocking descriptors
and kernel polling. A slow client can occupy one serial dispatch for that bounded
period; this is not a high-throughput concurrent server.

| ID | Route |
|---|---|
|1|`/machine/tka/init/begin`|
|2|`/machine/tka/init/finish`|
|3|`/machine/tka/bootstrap`|
|4|`/machine/tka/sync/offer`|
|5|`/machine/tka/sync/send`|
|6|`/machine/tka/disable`|
|7|`/machine/tka/sign`|
|8|`/machine/tka/affected-sigs`|
|9|Trusted registry upsert|
|10|Trusted registry remove|
|11|Trusted map/list read|

RPCs1,2,6 require admin. All eight bind JSON `NodeKey` to the registered key of
the header NodeID. `/sign` authenticates that caller but resolves the signed
target from the signature's embedded node public key; it need not be the caller.
Registry and map commands require admin and may use header NodeID0.

Registry upsert takes `{NodeID,NodeKey,RotationPubkey,Signature?}`. `NodeKey` is
`nodekey:`hex and `RotationPubkey` is a32byte base64 Ed25519 public key. IDs and
node keys are unique. Optional `Signature` is a base64/byte-array upstream NKS;
nonempty signatures require an active authority and valid authorization. A key
change clears the old signature. Omitting Signature preserves it only when the
key is unchanged. Unsigned nodes may be registered and signed later; this does
not itself authorize them to peers. Remove takes `{NodeID}`. Map/list takes `{}`
and returns `{TKAInfo,Revision,Nodes:[{NodeID,NodePublic,RotationPubkey,KeySignature}]}`.
`RotationPubkey` is the stored32byte base64 public key, exposed for adapter reconciliation.
Inactive and pending authority produce `TKAInfo:null`; active produces `{Head}`; disabled
produces `{Disabled:true}`. Unsigned nodes have `KeySignature:null`.
Revision advances after each durable mutation. An exact registry upsert retry (same ID,
node key, rotation key and omitted or identical signature) is nonmutating: it preserves the
revision and pending initialization, including after restart. This also permits replay of an
already accepted historical signature without reauthorizing it under a later authority.
Adapters must propagate these full values to initial/delta map responses and arrange notifications.

## State transitions and durable publication

Initialization binds a signed pending genesis to the initiating NodeID and the
frozen registry. Any actual registry change invalidates pending initialization; an exact
upsert retry does not. Finish requires exactly one valid direct signature for every frozen
node, including its registered wrapping public key. A different initiator, partial roster, stale
roster, invalid signature or invalid support-disablement secret rejects. Optional
SupportDisablement is retained separately and never disables the authority.
Pending genesis is not visible in map or bootstrap responses.

Sync uses the authority unit's fork choice, offer sampling and intersection.
Interactive sync additionally requires the supplied Head to equal the resulting
chosen head; mismatch rejects the candidate. Noninteractive sync validates the
head encoding but permits a divergent remote head. Disable requires admin, the
current head and a valid bounded secret. A disabled authority remains available
for bootstrap's disablement secret and cannot be reinitialized in this profile.

Each mutating request operates on an inactive candidate slot, including registry,
signatures, pending state, support/disablement secrets and authority. The complete
response is encoded and checked against capacity **before** persistence. Only
then is a complete snapshot streamed to storage, synced, atomically renamed and
the directory synced. A successful commit is followed by an infallible live-slot
switch. Pre-rename errors discard the candidate and return503. Post-rename fsync
uncertainty exits74 immediately, without rollback or further serving. Exit74 also
denotes failed storage cleanup, including during initialization; it means a
storage fail-stop, not a definite successful commit. A transport
failure after publication remains an inherently ambiguous client outcome; the
adapter must reconcile through state reads.

The semantic snapshot is version1: one128byte little-endian metadata frame,
then each node's88byte record and optional signature frame, optional support and
disablement secret frames, then each retained typed AUM frame in insertion order.
Metadata holds status, node count, pending initiator, secret lengths, revision,
authority count and a version marker. Node records contain ID, signature length,
authorization-state index, raw node key and raw rotation key. Storage adds its
own framing, version, ordered BLAKE2s integrity chain and strict permission/type
checks; see `om/store/README.md`.

AUMs retain typed reconstruction (`tkamodel keep=1`), not merely canonical wire
serialization: an empty-but-present update metadata map must survive restart.
Recovery reboots/replays and verifies every AUM, registry uniqueness, structural
bounds, state status and every stored node signature against the historical
state at which it was accepted. This permits retaining a now-revoked signature
for affected-sigs/map propagation without treating it as currently authorized.
Recovery rechecks support secrets against genesis and disablement secrets against
the current authority. Corruption never
falls back to a temporary snapshot or an empty installation.

## Native loop lifecycle

Every Omega loop has a finite safety bound. To avoid an eventual request-count
trap, a quiescent epoch of100000dispatch iterations ends in a controlled exec of
`/proc/self/exe --resume`. The running inode, not an installation pathname or
argv0, is used. FD64holds the directory,65the writer lock and66the listener across
exec; first-epoch handoff refuses occupied targets. Resume validates inherited
descriptors, exact lock/listener addresses, directory/socket ownership and modes,
then reloads the committed snapshot. It never binds, initializes or unlinks.
Queued connections stay on the same listener and the PID is unchanged. Every
accepted connection is closed before rollover. Exec failure exits76 and never
retries or unlinks. The native exec operation supplies an empty environment;
this service does not depend on environment configuration. Linux procfs and an
unchanging effective UID are prerequisites.

## Limits and tests

Single tailnet;64registered nodes;128AUMs per authority;65536bytes per raw JSON
request/response, with a4095token/depth32JSON parser and256members per object; individual crypto/model
objects at most65536bytes, further constrained by JSON/base64 envelope capacity;
secrets at most1024bytes. Response overflow is413before mutation. Resource limits
are explicit rejections, not silent truncation or history eviction. Known-field
matching follows Go's ASCII case folding plus the Kelvin-sign and long-s Unicode
aliases; duplicate aliases are rejected. Exact decoded JSON key duplicates are
rejected globally. Signature-map NodeID keys follow Go signed-decimal parsing,
including leading plus/zeros, with duplicate decoded IDs rejected and registry
IDs restricted to positive int64 values. Unknown fields are ignored. The
32byte rotation-key registry requirement and disabled-state reinitialization
restriction are explicit local profile limits, not general upstream limits.

Run `GO=/path/to/go1.26.8 REGEN=1 sh cmd/tkad/test/run.sh` to regenerate fixtures
through real pinned `tailscale.com/tka`, build the native binary, and exercise
all eight RPCs plus registry/map, authorization errors, malformed frames,
initialization races, restart, historical revocation and disk-write failure.
Test-only syscall-boundary variants prove one-shot begin/commit failure recovery
without process restart and fatal handling of post-rename directory-fsync failure.
A two-dispatch epoch variant checks queued connections, stable PID/listener,
retained writer exclusion and missing/swapped resume-descriptor refusal.
A completed-response admin-bypass mutant must be detected; a trapping mutant
must be rejected as an invalid test completion. Tests use isolated temporary
state directories and no live services. These are host/socket regression tests,
not stock-client end-to-end or constant-time qualification.

### Third-party material

The service composes Omega units adapted from Tailscale; their BSD-3-Clause
notices remain in `om/tka/tailscale.LICENSE` and
`om/tkasig/test/tailscale.LICENSE`. The Go fixture generator imports the pinned
upstream module and contains no copied upstream source. Its deterministic
private test keys are public fixtures, never deployment keys.
