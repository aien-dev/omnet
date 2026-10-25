#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../../.." && pwd)
if [ "$#" -eq 0 ]; then
    omc=$("$root/tools/omc.sh")
else
    omc=$1
fi
exec python3 "$here/run.py" "$omc"
