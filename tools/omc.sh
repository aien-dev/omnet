#!/bin/sh
# Build the pinned seed-born Omega compiler and print its path.
# The compiler is born from aien-dev/omega-mv at the commit in omega.pin by the
# repository's own seed chain; its digest must equal the pinned digest.
# Usage: tools/omc.sh            -> prints path of a verified omc on stdout
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
pin_commit=$(awk '$1 == "omega-mv" { print $2 }' "$root/omega.pin")
pin_sha=$(awk '$1 == "omc-sha256" { print $2 }' "$root/omega.pin")
src="$root/build/omega-mv"
omc="$src/seed/out/omc"

if [ ! -d "$src/.git" ]; then
	mkdir -p "$root/build"
	git clone -q --filter=blob:none https://github.com/aien-dev/omega-mv.git "$src" >&2
fi
if [ "$(git -C "$src" rev-parse HEAD)" != "$pin_commit" ]; then
	git -C "$src" fetch -q origin "$pin_commit" >&2
	git -C "$src" checkout -q --detach "$pin_commit" >&2
fi
if [ ! -x "$omc" ] || [ "$(sha256sum "$omc" | cut -d' ' -f1)" != "$pin_sha" ]; then
	(cd "$src" && sh seed/omega-from-seed.sh) >&2
fi
# The birth script accepts any fixpoint and rewrites its own digest file, so the
# pinned digest is checked here, never seed/out/omc.sha256.
got=$(sha256sum "$omc" | cut -d' ' -f1)
if [ "$got" != "$pin_sha" ]; then
	echo "omc.sh: omc digest $got does not match pin $pin_sha" >&2
	exit 1
fi
echo "$omc"
