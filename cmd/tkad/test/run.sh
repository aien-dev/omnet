#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
if [ "${REGEN:-0}" = 1 ] || [ ! -f "$root/cmd/tkad/test/fixture.json" ]; then
    (cd "$root/om/tka/test/oracle" && "${GO:-go}" run -mod=readonly "$root/cmd/tkad/test/fixture.go") > "$root/cmd/tkad/test/fixture.json"
fi
bin=$(sh "$root/tools/build-tkad.sh")
python3 "$root/cmd/tkad/test/smoke.py" "$bin"
python3 "$root/cmd/tkad/test/mutant.py" "$root" "$bin"
python3 "$root/cmd/tkad/test/rollover.py" "$root" "$bin"
python3 "$root/cmd/tkad/test/directory.py" "$bin"
python3 "$root/cmd/tkad/test/faults.py" "$root" "$bin"
