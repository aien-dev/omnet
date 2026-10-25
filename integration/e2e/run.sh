#!/bin/sh
# Test-only. Prerequisites (acquisition/build may use the network):
#   GO=/path/to/go GOTOOLCHAIN=auto sh integration/e2e/build-clients.sh
#   GO=/path/to/go GOTOOLCHAIN=auto sh integration/headscale/build.sh
#   sh tools/build-tkad.sh
# Then, on Linux with unprivileged user/network namespaces enabled:
#   sh integration/e2e/run.sh [--keep] [--result /absolute/result.json]
# If user namespaces are prohibited, explicitly opt into namespace setup only:
#   sh integration/e2e/run.sh --sudo-netns [--keep] [--result /absolute/result.json]
# This uses sudo -n, creates a NEW network namespace with loopback and a dummy
# link (no egress), then drops all UID/GID privileges to the invoking user before
# creating state or launching any daemon. No implicit sudo or host-network fallback.
# Requires python3, util-linux unshare, iproute2 ip. Never uses the host tailnet,
# Docker, a host network interface, or a global tailscaled socket.
# --keep retains private temporary logs/state (including disposable private keys).
# Default cleanup removes only the directory created by this invocation.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
for tool in unshare ip python3; do
    command -v "$tool" >/dev/null || { printf 'NOT_RUN: required tool %s unavailable\n' "$tool" >&2; exit 77; }
done
OUTER=$(readlink /proc/self/ns/net)
BIN=${E2E_BIN_DIR:-"$ROOT/build/e2e"}
HS=${HEADSCALE_BIN:-"$ROOT/build/headscale"}
TKAD=${TKAD_BIN:-"$ROOT/build/tkad"}
if [ "${1:-}" = "--sudo-netns" ]; then
    shift
    UID_NOW=$(id -u)
    GID_NOW=$(id -g)
    [ "$UID_NOW" -ne 0 ] || { printf 'NOT_RUN: invoke --sudo-netns as the ordinary test user\n' >&2; exit 77; }
    exec sudo -n unshare --net --pid --fork --kill-child \
        python3 "$ROOT/integration/e2e/lifecycle.py" --outer-netns "$OUTER" \
        --run-uid "$UID_NOW" --run-gid "$GID_NOW" \
        --bin-dir "$BIN" --headscale "$HS" --tkad "$TKAD" "$@"
fi
exec unshare --user --map-root-user --net --pid --fork --kill-child \
    python3 "$ROOT/integration/e2e/lifecycle.py" --outer-netns "$OUTER" \
    --bin-dir "$BIN" --headscale "$HS" --tkad "$TKAD" "$@"
