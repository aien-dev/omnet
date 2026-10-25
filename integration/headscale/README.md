# Headscale adapter

`headscale.patch` applies to Headscale **v0.29.6**, commit
`a2b1d7863926834e94479dcdd91ab344a9356bd0` (see `headscale.pin`). No fork is
vendored. The patch adds Go transport/authentication glue to the existing
Headscale server. TKA parsing, signatures, authority transitions and durable
accepted signatures remain in the Omega daemon.

## Build

From the Omnet checkout, with Git, a Go launcher supporting automatic toolchain
selection, and network access to GitHub and the Go module proxy:

```sh
GO=/path/to/go sh integration/headscale/build.sh
# output: build/headscale (override with HEADSCALE_OUTPUT)
sh tools/build-tkad.sh
```

The builder clones the pinned tag into a disposable directory, verifies its
commit, applies the patch, and builds using `go1.27.3` and the patched module
checksums. It removes only its own temporary checkout. Dependencies are not
vendored. Headscale requires Go 1.27.3. Its original x/tools v0.49.0 cannot read
that compiler's V5 export data, so the patch pins x/tools v0.50.0 and includes
regenerated Node views/clones. Re-generation requires Go on `PATH`:
`go generate ./hscontrol/types` in the patched source.

## Isolated operation

Provision tkad exactly as described in `cmd/tkad/README.md`, then start both
processes as the **same UID**, in the same network namespace. Use private state,
private sockets and an isolated Headscale configuration, not an existing tailnet.
The two required adapter settings are environment variables, not YAML keys:

```sh
OMNET_TKAD_SOCKET=/absolute/private/tkad/tkad.sock \
OMNET_TKAD_ADMIN_USER_ID=1 \
  build/headscale --config /absolute/private/headscale.yaml serve
```

`OMNET_TKAD_ADMIN_USER_ID` must be the explicitly selected numeric Headscale user
ID. The example value `1` is not a default. It may be configured before that user
is created; the isolated E2E harness creates the user and checks the returned ID.
Only currently unexpired, untagged nodes owned by that user receive the admin
assertion. Noise machine identity and the current unique node key must both match. A body
cannot assert a user, NodeID or administrator status. Setting only one variable
is an error. Setting neither leaves ordinary upstream Headscale behavior **only on
a database that has never used this adapter**; once adapter state exists (a
checkpoint row or any node with a tailnet-lock key), the server refuses to start
instead of publishing maps without TKA state.

Headscale still needs a nonempty DERP map, even in isolation. The E2E harness
supplies a private region and private client sockets; it never uses the live
Tailscale socket. See `integration/e2e/` for the runnable stock-client scenario.

## Persistence and failure behavior

The patch adds `nodes.tka_key`, `nodes.tka_signature` and a one-row
`omnet_checkpoints` table through an append-only migration. NLKey and the pending
submitted NKS are committed with Headscale's desired registration tuple, including
interactive auth callbacks. The pending signature is an outbox, **not** a trusted
map signature. Only a tkad snapshot supplies map signatures.

A shared publication barrier serializes identity changes, reconciliation,
Noise/admin resolution and map-frame construction. Reconciliation reads committed
SQL, rejects ambiguous or speculative identities, removes daemon orphans and
vacates obsolete keys before claiming desired keys, including key-reuse cycles
after an outage. Accepted-signature readback resolves an ambiguous IPC outcome
without replaying a historical signature after key removal. An unchanged registry
causes no upsert, including after adapter restart, so it does not cancel pending
initialization.

A definitively rejected pending signature is retried without a signature. Only
after that unsigned tuple succeeds is the rejected outbox cleared. A new key is
then unsigned; an unchanged key retains its existing Omega-accepted signature.
The submitting registration gets an explicit signature error, but unrelated
nodes keep working. IPC authentication failures, failed unsigned retries, 5xx
and lost replies remain fail-closed and retain the outbox for recovery.

All eight raw GET RPC bodies and replies are forwarded without re-encoding.
Initial, self, peer, changed-peer, non-streaming and queued map responses use one
fresh daemon snapshot. Key-only patches become full maps so an unsigned new key
cannot retain an old signature through JSON omission. Stale sessions cannot
restore an old node key through MapRequest. Revision changes wake streams even
when the authority head is unchanged (for example, signing a node).
Non-key patches never carry signatures. Each stream writes its frozen frames in
order after releasing the global barrier, with bounded writes and a stop deadline
that cannot be lengthened by a queued frame. Client cancellation does not mark
the daemon unhealthy. Interactive reauthentication retains the signature challenge
and then requires upstream authentication; the old Noise identity never silently
rotates the key or replaces an AuthURL.

Daemon connection/read/shape failures block publication and close existing map
streams; no stale-cache, empty-signature, disabled-state or nil-TKAInfo fallback
is used. An absent daemon refuses server startup. A reachable daemon plus a
pending registration permits authenticated retries and administrative repair while
unresolved transport/registry failures block map/TKA publication. Older Headscale
nodes without NLKey must re-register; there is no invented rotation key. A committed
identity whose outbox cannot be reconciled is not reported as successful registration.
Post-commit policy refresh runs even when reconciliation will reject registration.

The durable observed-revision floor rejects an empty/older daemon snapshot after
adapter restart. It is **not authenticated rollback protection**, and cannot
identify an arbitrary different authority with a higher revision. Back up and
restore the Headscale database and tkad directory together. Same-UID processes
and root are trusted and can alter either store. Outages do not revoke already
installed peer connectivity. This is not a separate-UID deployment profile or a
production security audit.

Limits remain one tailnet, 64 nodes, 128 AUMs and 64-KiB IPC JSON messages. Every
committed mutation must still be servable through the 64-KiB registry response:
an accepted node signature is stored in canonical form, so ignored CBOR fields
cannot pad it, and a candidate that would exceed the response limit is rejected
with 413 before it is persisted. A saturated registration or map admission
answers 503 instead of queueing on the publication barrier, and a TKA RPC from
an unregistered Noise identity is refused before any daemon work. IPC and
raw RPC read/write phases have absolute deadlines; a bounded serial daemon and
publication barrier trade throughput for simple ordering. New registrations beyond
64, zero node keys, duplicate keys even across users on one machine, and signatures
above 48,768 raw bytes are rejected before persistence.

## Validation

Focused adapter regressions, upstream control/state/mapper/types suites, SQLite
migration tests and the isolated stock-client lifecycle passed. Reproduce focused tests
in a checkout at the pinned commit with `headscale.patch` applied:

```sh
GOTOOLCHAIN=go1.27.3 go test -count=1 -run '^TestOmnet' ./hscontrol ./hscontrol/state
GOTOOLCHAIN=go1.27.3 go test -count=1 -run '^TestSQLite' ./hscontrol/db
```

Build and run the stock clients separately from the library suite:

```sh
GO=/path/to/go sh integration/e2e/build-clients.sh
GO=/path/to/go sh integration/headscale/build.sh
sh tools/build-tkad.sh
sh integration/e2e/run.sh --result /tmp/omnet-e2e-result.json
# If user namespaces are prohibited, explicitly request privileged namespace setup:
sh integration/e2e/run.sh --sudo-netns --result /tmp/omnet-e2e-result.json
```

The launcher requires Linux `unshare`, `ip` and Python3. It creates a fresh network
namespace with loopback and a dummy link, no egress or host interfaces. Privileged
setup drops UID/GID privileges before starting the daemons. Clients use private state
and explicit sockets. Default cleanup removes the invocation's disposable state;
`--keep` retains it, including private test keys, for debugging. Do not publish those logs.
The receipt includes only scenario verdicts and public artifact hashes.

The successful lifecycle reports 13 PASS records including provenance. It covers
initialization, unsigned-peer filtering, signing, authenticated rotation, authority
removal and re-signing, restart recovery, non-owner denial, daemon outage/recovery,
disablement and disabled restart. This is netmap admission evidence, not packet delivery.

The tests exercise durable outbox/revision persistence, committed identity
refusal, same-machine cross-user duplicate-key prevention, expired-owner denial,
historical-signature readback, definitive rejection isolation, ambiguous replies,
unchanged restart reconciliation, interactive authentication, old-map rollback
refusal, full-node signature clearing, signature-free non-key patches, cancelled
requests, stopped/slow writers, key-reuse recovery cycles, policy refresh after
reconciliation failure, and map outage closure. Transport fixtures do not replace
the real Omega suite or stock-client E2E. The parent integration run supplies those
receipts. For broader upstream regression coverage run the normal Headscale unit
suites separately; Docker-based Headscale integration tests are not required by
this adapter's isolated stock-client harness.

## Deployment gate and recovery plan

The [Tailworm disclosure](https://tailworm.com/) also describes SSH forwarding,
app connectors, unauthenticated control-server exhaustion, hostile DERP responses
and Serve exposure. This adapter does not patch those components. Signature-based
node admission does not stop an already authorized compromised device from using
its existing permissions, or protect signing keys on a compromised endpoint.
Qualify upstream fixes and feature-specific hardening separately; passing this
suite must never be reported as “Tailworm fixed” or “the network is secure.”

**Not approved for live deployment.** The isolated lifecycle is a control-plane
receipt, not a production security audit or proof of packet delivery. Keep this
adapter off the live controller until the following gates have evidence:

- **Every committed node must carry an NLKey before activation, and the roster
  must fit the profile (at most 64 nodes, unique node keys, no ambiguous
  identity).** Reconciliation fails as a whole while any node lacks one, which
  closes map streams and answers new map polls 503 for the entire tailnet until
  that node re-registers or is deleted. Nodes created before this migration have
  a null NLKey, so activating in place over an existing database blackouts
  control until every node, including offline ones, re-registers. A running
  client may not re-register on its own. Verify with `SELECT` on `nodes` that no
  row has a null `tka_key` and that the count is within 64, immediately before
  the change window.
- Inventory the actual clients, registered nodes (including offline nodes), NLKeys,
  authority history and expected message sizes against this bounded profile.
  The tested client is v1.102.0; other versions need their own qualification.
  Every accepted node signature occupies part of one 64-KiB registry response.
  A mutation that would not fit is now rejected with 413 instead of being
  committed unreadable, so qualification must show the real roster plus signature
  history stays below that response limit for the operational horizon. The 128-AUM
  authority limit has no compaction path; plan for it before exhaustion.
- Establish and test an administration path independent of this tailnet, including
  console or direct SSH access. An existing tailnet SSH session is not a recovery
  path: controller loss, key rotation or signature rejection can prevent reconnect.
- Select the owner user by numeric ID and enumerate every unexpired, untagged
  device that will receive administrator privileges. Ownership is user-wide, not
  restricted to one operator device; a newly enrolled unsigned owner device also
  qualifies, so its enrollment credentials are part of the administration boundary.
- Keep at least two separately held signing keys and protect the disablement
  secret offline. Do not store signing private keys or recovery secrets on the
  controller. Test operator recovery using disposable keys first. A nonempty
  `SupportDisablement` value submitted at `init/finish` is stored in the tkad
  snapshot, so a same-UID controller compromise can read and use it: either
  accept that, or never submit it and keep the secret off the controller
  entirely (the client then needs its own copy for `tailscale lock disable`).
- Rehearse the database migration, paired backup/restore, client reconnect and
  packet-level signed/unsigned-peer behavior in a separate representative network.
  Include the phone and the actual SSH path before scheduling a live change.
- Review the same-UID trust boundary and untrusted-client availability limits.
  Controller compromise grants access to tkad state; Omega is not a sandbox for
  the controller. Source review does not establish constant-time behavior.
  Registration and map admission are bounded (a saturated adapter answers 503
  "busy" instead of queueing), and a TKA RPC from an unregistered Noise identity
  is refused before any shared persistence work. That bounds amplification; it
  does not make the control plane immune to load.
- On SQLite, a stock v0.29.6 binary refuses a migrated database at its schema
  check, and the migration has no rollback. Treat the adapter as a one-way
  migration for that database: keep the original binary and pre-migration
  database together, and rebase and re-qualify the patch for every Headscale
  upgrade. PostgreSQL is unqualified and does not perform that schema check, so
  it would start stock and silently drop Tailnet Lock state.
- Run tkad and Headscale as separate units under the same UID, in the same
  network namespace, with tkad started first. Never put `--init` in a unit file.
  Handle the daemon's exit codes distinctly: 73 is a refused start (do not
  restart in a loop), 74 is a deliberate storage fail-stop, 76 is a failed
  rollover or exec. Restored state directories must be 0700/0600, owned by the
  service UID, without hard links or a symlinked final component, and no tkad
  process may be running while the directory is copied.

### Quiescent backup and restore

This is the required ordering for a rehearsal, not a claim that a live restore
has been tested:

1. Stop Headscale and prevent its automatic restart so no registry or TKA request
   can be submitted. Stop tkad and prevent its automatic restart.
2. Capture a consistent Headscale database using the database's supported backup
   mechanism, plus the tkad state directory, controller configuration, policy,
   artifact hashes and both adapter settings. Keep SQLite WAL/journal consistency;
   copying a live main database file alone is not a backup.
3. Keep the pair together, access-restricted and labelled with one capture ID.
   The snapshot includes secrets. Do not put it in this public repository.
4. Restore both stores into an isolated environment under trusted ancestors and
   the intended UID/modes. Never restore one store alone, decrement the observed
   revision floor, or use `--init` to bypass missing/corrupt state.
5. Start tkad without `--init`, then Headscale with both adapter settings. Check
   the authority head, roster and accepted signatures, then reconnect clients.
   A checksum-valid backup is not proof that clients accept its authority history.

The revision floor detects some stale restores; it is not authentication of the
backup. Rolling both stores back can evade that floor and conflict with client
state. If a rehearsal cannot reconcile the saved authority with current clients,
keep publication stopped and recover the correct stores rather than resetting
the authority.

### Change window and interruption

Before enabling Tailnet Lock, preserve the pre-migration database and original
controller binary/configuration. A pre-activation rollback restores that original
set, not an older binary against the migrated database.

After activation, there is **no transparent downgrade** to ordinary Headscale:
removing the adapter variables does not safely undo the authority already stored
by clients. On SQLite a stock binary refuses the migrated database outright; on
PostgreSQL it would start and silently drop Tailnet Lock state. To make that
failure explicit, the adapter now refuses to start when both settings are absent
and the database already records adapter state (a checkpoint row or any node with
a tailnet-lock key). Prefer repair/roll-forward using the paired stores.
Disabling Tailnet Lock is an explicit security downgrade requiring the owner's
approval, a valid recovery secret and verified client convergence. Disablement is
permanent for that database: a disabled authority cannot be reinitialized, and a
fresh `--init` directory starts at revision 0, which the durable floor rejects.
Re-enabling Tailnet Lock therefore needs a new Headscale database. Run `disable`
only while the adapter is active, so clients can fetch the stored disablement
secret; a client that misses it needs `tailscale lock local-disable` locally.
Do not present disablement as a reversible toggle.

The revision floor catches a lower daemon revision, not an arbitrary different
authority at an equal or higher revision, and it advances before reconciliation.
Restoring an older database beside a newer tkad therefore removes the nodes and
signatures the older database lacks. That is why the stores must always be
restored together from one capture.

A controller restart interrupts control-plane requests and map streams. Existing
peer paths may continue, but new connections, relay-dependent paths, registration,
rotation and SSH reconnect are not guaranteed. A tkad outage blocks publication;
it does not revoke existing data-plane connectivity. No live-service interruption
is part of the isolated build/review workflow.

## Third-party notices

The patch includes context from Headscale and regenerated Tailscale-derived view
code. Their BSD-3-Clause notices are `headscale.LICENSE` and `tailscale.LICENSE`.
New Omnet glue is covered by the repository license. No upstream cryptographic
implementation is added to Headscale by this patch.
