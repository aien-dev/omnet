#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
. "$here/headscale.pin"
go=${GO:-go}
go=$(command -v "$go")
case "$go" in /*) ;; *) go=$(pwd)/$go ;; esac
PATH=$(dirname -- "$go"):$PATH
GOTOOLCHAIN=$HEADSCALE_GO_TOOLCHAIN
export PATH GOTOOLCHAIN
out=${HEADSCALE_OUTPUT:-$root/build/headscale}
case "$out" in /*) ;; *) out=$(pwd)/$out ;; esac
work=$(mktemp -d "${TMPDIR:-/tmp}/omnet-headscale-build.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
git clone --quiet --depth 1 --branch "$HEADSCALE_VERSION" "$HEADSCALE_URL" "$work/source"
actual=$(git -C "$work/source" rev-parse HEAD)
if [ "$actual" != "$HEADSCALE_COMMIT" ]; then
    printf '%s\n' 'Headscale tag no longer matches pinned commit' >&2
    exit 1
fi
git -C "$work/source" apply "$here/headscale.patch"
mkdir -p -- "$(dirname -- "$out")"
(
    cd -- "$work/source"
    "$go" build -trimpath -o "$out" ./cmd/headscale
)
printf '%s\n' "$out"
