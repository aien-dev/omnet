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
is an error. Setting neither leaves ordinary upstream Headscale behavior.

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

Limits remain one tailnet, 64 nodes, 128 AUMs and 64-KiB IPC JSON messages. IPC and
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

## Third-party notices

The patch includes context from Headscale and regenerated Tailscale-derived view
code. Their BSD-3-Clause notices are `headscale.LICENSE` and `tailscale.LICENSE`.
New Omnet glue is covered by the repository license. No upstream cryptographic
implementation is added to Headscale by this patch.
