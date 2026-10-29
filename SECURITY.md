# Security policy

## Reporting a vulnerability

Report privately. Do not open a public issue, pull request or discussion about it.

1. GitHub: open this repository's Security tab and choose "Report a vulnerability". This
   creates a private advisory that only the maintainers can see. If that option is not shown,
   private vulnerability reporting has not been enabled for this repository yet; use email.
2. Email: drake@aienos.com with the subject `[omnet] security report`.

Include the commit or release you tested, the component (path), steps to reproduce, and what an
attacker gains. If the report involves a secret, say where it was exposed and do not send the
secret itself. Encrypted mail is not required; do not post proof-of-concept payloads publicly.

## Response targets

This project has one maintainer; the targets below are best effort and stated honestly.

- Acknowledgement: within 3 working days.
- Triage and severity: within 7 days of acknowledgement.
- Fix or mitigation for confirmed issues: aim for 30 days for high and critical, 90 days
  otherwise, with a status update at least every 14 days until closed.
- Disclosure: coordinated. An advisory is published with credit (unless you ask otherwise)
  once the fix is on the default branch. Default embargo 90 days, negotiable.

## Scope

In scope:

- An Omega unit under `om/` (BLAKE2s, BLAKE2b, SHA-512, Ed25519, Argon2, codec, CBOR, JSON,
  TKA, tkasig, store, quantity) that accepts a forged signature, rejects a valid one, reads or
  writes out of bounds, or traps on attacker-supplied input (a reachable trap is a
  denial-of-service bug).
- A wrong authorization decision in the Tailnet Lock (TKA) model, `om/tka/`, `om/tkasig/`, or
  in the `tkad` daemon RPC handlers under `cmd/tkad/`.
- The `tkad` IPC framing in `cmd/tkad/socket.om`: oversized or malformed headers or bodies,
  missing deadlines, or a way to bypass the admin assertion or NodeKey binding.
- Durable state in `om/store/` and `cmd/tkad/state.om`: a crash, rename or short write that
  leaves a snapshot that recovery accepts but should refuse, or a check-then-use on a path.
- The Headscale adapter patch in `integration/headscale/headscale.patch`: an unauthenticated
  client reaching daemon work, a map published without TKA state, or identity taken from
  remote JSON.
- `tools/omc.sh` accepting a compiler whose digest does not equal `omega.pin`.

Out of scope:

- Test oracles and vector generators (Go and Python under `*/test/`, `integration/e2e/`); they
  never ship. Upstream Headscale, Tailscale and Go code outside the committed patch.
- Timing side channels: the code is not constant-time audited and makes no such claim.
- Attacks by a process running as the same UID as `tkad`, or as root. The README and
  `cmd/tkad/README.md` state that this local boundary is trusted.
- The Omega compiler itself; report it to `aien-dev/omega-mv`.

## Supported versions

Only the default branch `main`; there is no release. Reports against older commits are welcome
but fixes land on the default branch only.

## Status

The daemon implements all eight TKA RPCs and has passed isolated end-to-end verification with
stock Tailscale clients. The README states this is not deployed tailnet protection, data-plane
qualification or a production security audit, and no live deployment is approved. There is no
certification and no bug bounty. See AUDIT_SCOPE.md for what to review and how to build and
test it.
