#!/bin/sh
# Bootstrap glue only; all test selection, controls and verdicts are Omega.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
omc=$(sh tools/omc.sh)
mkdir -p build/security3
"$omc" < qualification/security3/run.om > build/security3/consumer-units
chmod +x build/security3/consumer-units
exec build/security3/consumer-units "$omc" --consumer-units
