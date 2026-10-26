#!/bin/sh
# Bootstrap glue only; every check and verdict is Omega.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
exec python3 "$root/om/quantity/test/run.py"
