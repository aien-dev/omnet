#!/bin/sh
# Test-only dependency acquisition. Run from any directory:
#   GO=/path/to/go GOTOOLCHAIN=auto sh integration/e2e/build-clients.sh
# Builds unmodified tailscale.com v1.102.0 from the checksum-verified Go module.
# The module proxy/checksum database and Go toolchain download require network;
# the lifecycle runner creates an isolated network namespace without egress.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
GO=${GO:-go}
OUT=${E2E_BIN_DIR:-"$ROOT/build/e2e"}
mkdir -p "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
export GOTOOLCHAIN=${GOTOOLCHAIN:-auto}
export GO111MODULE=on
"$GO" mod download -json tailscale.com@v1.102.0 > "$OUT/tailscale-module.json"
SRC=$(python3 - "$OUT/tailscale-module.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
if m.get('Error') or m.get('Version') != 'v1.102.0' or not m.get('Sum'):
    raise SystemExit('pinned Tailscale module acquisition failed')
origin = m.get('Origin', {})
if origin and origin.get('Hash') != '35283c95445fb198af1ce708dac05714bdfaa037':
    raise SystemExit('unexpected Tailscale v1.102.0 source revision')
print(m['Dir'])
PY
)
(cd "$SRC" && "$GO" build -trimpath -buildvcs=false -o "$OUT/tailscale" ./cmd/tailscale)
(cd "$SRC" && "$GO" build -trimpath -buildvcs=false -o "$OUT/tailscaled" ./cmd/tailscaled)
"$GO" version -m "$OUT/tailscale" > "$OUT/tailscale.buildinfo"
"$GO" version -m "$OUT/tailscaled" > "$OUT/tailscaled.buildinfo"
python3 - "$OUT" <<'PY'
import hashlib, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
module = json.loads((out / 'tailscale-module.json').read_text())
manifest = {
    'version': 'v1.102.0',
    'source_revision': '35283c95445fb198af1ce708dac05714bdfaa037',
    'module_sum': module['Sum'],
    'sha256': {name: hashlib.sha256((out / name).read_bytes()).hexdigest()
               for name in ('tailscale', 'tailscaled')},
}
(out / 'stock-client.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
printf 'Built stock v1.102.0 clients in %s\n' "$OUT"
