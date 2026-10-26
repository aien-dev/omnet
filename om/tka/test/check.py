#!/usr/bin/env python3
"""A mutant must complete normally with exactly the expected record count."""
import pathlib
import sys

want = pathlib.Path(sys.argv[1]).read_text().splitlines()
got = pathlib.Path(sys.argv[2]).read_text().splitlines()
if len(want) != len(got):
    for i, (a, b) in enumerate(zip(want, got)):
        if a != b:
            print(f"first difference record {i + 1}: expected {a[:240]}, got {b[:240]}")
            break
    raise SystemExit(f"FAIL record count: expected {len(want)}, got {len(got)}")
bad = [i for i, pair in enumerate(zip(want, got)) if pair[0] != pair[1]]
if sys.argv[3] == "mutant":
    if not bad:
        raise SystemExit("FAIL mutant survived")
    print(f"PASS mutant: completed {len(got)} records, {len(bad)} differ")
else:
    if bad:
        for i in bad[:10]:
            print(f"record {i + 1}: expected {want[i][:240]}, got {got[i][:240]}")
        raise SystemExit(f"FAIL {len(bad)} differing records")
    print(f"PASS {len(got)} differential records")
