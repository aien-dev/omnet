#!/bin/sh
# Test-only coordinator; all production storage is Omega.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
exec python3 "$root/om/store/test/run.py"
