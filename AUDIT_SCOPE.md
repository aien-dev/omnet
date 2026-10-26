# Audit scope

Written for an outside, independent security audit. Revision described:
`83f605b147205bd912b085afdcf24402df24b5e5` on `main`, 2026-10-26. Everything below is taken from
the repository's own files at that revision; items marked NOT_RUN were not executed while writing
this document.

## What this repository is

omnet rewrites security-critical network code in Omega (`.om`), a language from
`aien-dev/omega-mv` whose compiler emits AArch64 Linux programs. The first project is the
server side of Tailscale Tailnet Lock (TKA) for self-hosted Headscale control servers. All TKA
logic, cryptography, parsing and durable state ship as Omega: the `om/` libraries and the `tkad`
daemon in `cmd/tkad/`. The Headscale adapter is a Go patch (`integration/headscale/`) that the
README describes as transport and authentication glue. Go and Python under `test/` directories
and `integration/e2e/` are test oracles and drivers and never ship. Status per README and
`docs/design/tailnet-lock.md`: implemented and verified in isolation; not deployed, not
production-qualified, not a production security audit.

## What to review, in priority order

1. `cmd/tkad/socket.om`, `cmd/tkad/rpc.om`, `cmd/tkad/adapter.om`, `cmd/tkad/main.om`. The
   AF_UNIX IPC service: a 20-byte request header, a JSON body of 0..65536 bytes, 3-second
   per-phase deadlines, the admin assertion byte (exactly 0 or 1) and the NodeID. Check that
   bad or oversized headers close without a reply, that every RPC binds JSON `NodeKey` to the
   registered key of the header NodeID, that RPCs 1, 2 and 6 and registry/map commands require
   admin, and that error bodies never echo request details or secrets.
2. `om/tka/tka.om`, `om/tka/tkastate.om`, `om/tka/tkapool.om`, `om/tkasig/tkasig.om`. The
   authority chain and node-key signature checks. Check fail-closed behaviour (design rule 3):
   parse and signature failures reject; unknown signed AUM kinds advance the hash chain as
   no-ops and never bypass authorization.
3. `om/ed25519/`, `om/sha512/`, `om/blake2s/`, `om/blake2b/`, `om/argon2/` (with
   `argon2pool.om`). Signature verification and hashing used for authority and the disablement
   secret. Check correctness against the committed vectors and the bounds on inputs. No
   constant-time claim is made.
4. `om/cbor/`, `om/codec/`, `om/json/`. Parsers of attacker-controlled bytes (CBOR AUMs and
   signatures, base64/hex, JSON RPC bodies). Check that every read has a capacity and that
   size limits are checked before parsing (design rule 1).
5. `om/store/store.om`, `om/store/storepool.om`, `cmd/tkad/state.om`. Durable snapshots,
   record framing and capacity charges (65536 records, 33554432 bytes). Check descriptor-based
   operation (design rule 2), recovery refusing missing or corrupt snapshots, and the
   charges described in `qualification/security3-store/README.md`.
6. `om/quantity/quantity.om`. Checked arithmetic used by the store charges.
7. `integration/headscale/headscale.patch`. Go glue added to Headscale v0.29.6: Noise identity
   resolution, the admin user ID setting, reconciliation, SQL migrations, publication barrier,
   bounded admission slots. Check that a caller's identity is resolved before daemon work, that
   startup refuses when adapter state exists but settings are missing, and that pending
   signatures are never treated as trusted map signatures.
8. `tools/omc.sh`, `tools/build-tkad.sh`, `integration/headscale/build.sh`. Supply chain: the
   compiler is cloned from GitHub at the pinned commit, built by its seed chain and checked
   against the pinned digest; the Headscale build verifies the pinned commit.
9. Test suite integrity: `tools/test.sh`, `om/*/test/run.sh`, `cmd/tkad/test/run.sh`,
   `cmd/tkad/test/mutant.py`. AGENTS.md requires a mutant check per unit that counts only when
   the driver completes and a result differs.

`.github/workflows/ci.yml` (added by the audit-readiness change) builds the pinned omc through
`tools/omc.sh` and runs `sh tools/test.sh` on a GitHub-hosted arm64 runner with Go installed for
the oracles; a second job publishes an SPDX SBOM artifact. Every action is pinned by commit sha
and the token is read-only.

## Trust boundaries

- Untrusted input: TKA RPC JSON bodies from Tailscale clients (relayed by the adapter), CBOR
  AUMs and node-key signatures inside them, Noise clients reaching Headscale, and on-disk
  snapshots at recovery time (validated, not trusted).
- Trusted: the local adapter. `cmd/tkad/README.md` states the 0700 directory and 0600 socket
  give a same-UID/root boundary only; there is no SO_PEERCRED check, and same-UID or root
  processes can act as the adapter, read secrets and change storage. The adapter must derive
  NodeIDs and admin assertions from its own identity model, never from remote JSON.
- Trusted: the Omega compiler at the commit and digest in `omega.pin`; the Headscale commit in
  `integration/headscale/headscale.pin`.
- Isolated: the end-to-end test runs in a new network/PID namespace with loopback and a
  dummy link, no egress, and drops privileges before starting daemons (`integration/e2e/run.sh`).

## Threat model summary

- Assets: the tailnet authority (trusted keys), accepted node-key signatures, the disablement
  secret, durable snapshot integrity, and the availability of map publication.
- Attackers considered: a remote Tailscale client or Noise peer sending malformed or hostile
  RPCs, CBOR or signatures; an ordinary registered client trying to forge or pad signatures; a
  non-owner trying to disable TKA; crashes, short writes and ENOSPC during storage.
- Defended: memory-safety bug classes are runtime traps in Omega (README table); bounded input
  sizes; fail-closed parsing and signature checks; canonical storage of accepted signatures
  with a 413 refusal when the registry would not fit a map response; 401 before daemon work for
  unknown identities; 503 instead of queueing under saturation.
- Not defended / explicitly out of scope: timing side channels ("not constant-time-audited");
  same-UID or root attackers; logic and protocol errors beyond tests and review; service-level
  resource exhaustion (reduced, not eliminated); a reachable trap is still denial of service;
  the durable revision floor is not authenticated rollback protection; power-loss durability,
  cross-namespace writer exclusion and packet delivery are not established.

## Build from source at a pin

Requirements from README: Linux on ARM64, `git`, POSIX `sh`, Python 3, and Go >= 1.26.5 for the
TKA differential oracle. The Headscale adapter build uses go1.27.3.

Compiler pin, from `omega.pin`:

- omega-mv commit `acb3f15cdc691b1b046b48b0dad0f9255a12ba4b`
- omc sha256 `734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61`

`tools/omc.sh` clones `https://github.com/aien-dev/omega-mv.git` into `build/omega-mv`, checks
out the pinned commit, runs `seed/omega-from-seed.sh`, and exits non-zero if the result's
sha256 differs from the pin. It checks the pin, not `seed/out/omc.sha256`.

```sh
tools/omc.sh                       # prints the path of a verified omc
sh tools/build-tkad.sh             # builds build/tkad from the om/ and cmd/tkad/ sources
GO=/path/to/go sh integration/headscale/build.sh   # optional adapter, output build/headscale
```

The Omega build needs an AArch64 Linux host. The Headscale and client builds need network access
to GitHub and the Go module proxy.

## Run every test

```sh
tools/test.sh
GO=/path/to/go GOTOOLCHAIN=auto sh integration/e2e/build-clients.sh
GO=/path/to/go GOTOOLCHAIN=auto sh integration/headscale/build.sh
sh tools/build-tkad.sh
sh integration/e2e/run.sh
```

- `tools/test.sh` runs every `om/*/test/run.sh` and `cmd/*/test/run.sh` with the pinned
  compiler and prints `PASS <unit>` or `FAIL <unit>` per suite; exit 0 only if all pass.
  `docs/design/tailnet-lock.md` records twelve suites passing at stage six. NOT_RUN here.
- `integration/e2e/run.sh` needs unprivileged user and network namespaces, `unshare`, `ip` and
  `python3`; otherwise it prints `NOT_RUN` and exits 77. `--sudo-netns` uses `sudo -n` to create
  the namespace and drops privileges before any daemon starts. The design document records 13
  PASS records. NOT_RUN here.
- Foreign-UID ownership fixtures in the store suite need root and were skipped in the recorded
  stage-four run.

## Known limitations and NOT_RUN

- Profile limits: one tailnet, 64 nodes, 128 authority updates, 64-KiB JSON messages. Large
  checkpoints and long histories can exceed this profile.
- The daemon does not authenticate remote Tailscale clients; the adapter does, and shares the
  daemon UID.
- One committed node without an NLKey blocks publication for the whole tailnet; SQLite cannot be
  downgraded in place; disablement is permanent for that database
  (`docs/design/tailnet-lock.md`, stage six).
- No constant-time claim; no claim of absence of vulnerabilities.
- All recorded verification is host and isolated-namespace evidence. No deployment, data-plane
  or power-loss testing.
- `qualification/security3-store/README.md` notes that absence of migration to checked
  quantities is not evidence of a bug in modules it did not touch.

## Dependencies and provenance

- No lockfile at the repository root. Go oracles carry their own `go.mod`/`go.sum` under
  `om/*/test/gen/oracle/`, `om/json/test/oracle/` and `om/codec/test/gen/tsoracle/`.
- Committed test vectors carry upstream notices next to them (RFC 7693, 8032, 8949, 9106,
  4648; Wycheproof, ZIP-215, BLAKE2 KAT licences). Tailscale and Headscale licences ship
  beside derived material (`om/tka/tailscale.LICENSE`, `integration/headscale/*.LICENSE`).
- Oracles in Go and Python do not ship.
- External services at build/test time: GitHub (omega-mv clone in `tools/omc.sh`; Headscale
  and Tailscale clones) and the Go module proxy.
- No GitHub Actions.

## Evidence

There is no `evidence/` directory. Verification results are recorded in prose in
`docs/design/tailnet-lock.md` (stages three to six, including controller SHA-256
`71ffcb5e6aed6bd6b2ec441b718220e2ad1d70d3fa767c728d104447f8668807` for the rebuilt Headscale
binary) and in `qualification/security3-store/README.md`. Receipts for this repository, where
filed, belong under `aien-dev/aien-receipts` `omnet/<sha>/`; whether any exist is unknown from
the repository. Receipts are append-only and never edited.
