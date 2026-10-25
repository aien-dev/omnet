#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused host-only JSON checks; generated mutants live only in build/test/json."""
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = ROOT / "build/test/json"
OUT.mkdir(parents=True, exist_ok=True)
OMC = Path(sys.argv[1]).resolve()
SOURCE = (HERE.parent / "json.om").read_text()
DRIVER = (HERE / "driver.om").read_text()


def build(source, name):
    src = OUT / f"{name}.om"
    src.write_text(source + "\n" + DRIVER)
    binary = OUT / name
    with src.open("rb") as inp, binary.open("wb") as out:
        result = subprocess.run([str(OMC)], stdin=inp, stdout=out, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(f"{name}: omc exit {result.returncode}: {result.stderr.decode()}")
    binary.chmod(0o755)
    return binary


def execute(binary, data, expected):
    result = subprocess.run([str(binary)], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    lines = result.stdout.decode("ascii").splitlines()
    if result.returncode != 0 or len(lines) != len(expected):
        return "abnormal", lines, result.returncode
    return ("match" if lines == expected else "mismatch"), lines, 0


go = os.environ.get("GO", "go")
subprocess.run([go, "build", "-mod=mod", "-o", str(OUT / "oracle"), "."], cwd=HERE / "oracle", check=True)
result = subprocess.run([str(OUT / "oracle")], stdout=subprocess.PIPE, check=True)
(OUT / "oracle.jsonl").write_bytes(result.stdout)
rows = [json.loads(line) for line in result.stdout.splitlines()]
data = "".join(row["mode"] + row["hex"] + "\n" for row in rows).encode()
expected = [row["want"] for row in rows]
binary = build(SOURCE, "driver")
status, lines, rc = execute(binary, data, expected)
if status != "match":
    for i, (actual, want) in enumerate(zip(lines, expected)):
        if actual != want:
            print(f"json: mismatch {i} {rows[i]['class']} input={rows[i]['hex'][:160]} want={want[:160]} got={actual[:160]}")
            if sum(a != b for a, b in zip(lines[:i+1], expected[:i+1])) >= 12:
                break
    raise SystemExit(f"json: FAIL {status} rc={rc} lines={len(lines)}/{len(expected)}")
for cls, count in sorted(collections.Counter(row["class"] for row in rows).items()):
    print(f"json: {cls} {count}/{count} PASS")

worst = [row for row in rows if row["class"] == "member-long-prefix"]
assert len(worst) == 1 and worst[0]["want"].startswith("O ")
assert len(bytes.fromhex(worst[0]["hex"])) == 65536
smoke_runs = 10
smoke_input = ((worst[0]["mode"] + worst[0]["hex"] + "\n") * smoke_runs).encode()
started = time.perf_counter()
status, _, rc = execute(binary, smoke_input, [worst[0]["want"]] * smoke_runs)
elapsed = time.perf_counter() - started
assert status == "match", (status, rc)
print(f"json: long-prefix smoke 256 distinct 250-byte keys, 65536-byte message, "
      f"{smoke_runs} parse/hash/encode records: {elapsed:.6f}s wall, "
      f"{elapsed / smoke_runs:.6f}s/record (includes process startup and pipe I/O) PASS")

vectors = json.loads((HERE / "vectors.json").read_text())["parse"]
golden_input = "".join("P" + row["input"].encode().hex() + "\n" for row in vectors).encode()
r = subprocess.run([str(binary)], input=golden_input, stdout=subprocess.PIPE, check=True, timeout=120)
got = r.stdout.decode().splitlines()
assert len(got) == len(vectors)
for row, line in zip(vectors, got):
    if row["output"] is None:
        assert line == "E", (row, line)
    else:
        assert line.startswith("O ") and line.split(" ")[2] == row["output"].encode().hex(), (row, line)
print(f"json: committed-vectors {len(vectors)}/{len(vectors)} PASS")

mutants = {
    "duplicates": ("if jsondupe t d id\nret 5", "if false\nret 5"),
    "unicode": ("ret 65533", "ret 65532"),
    "depth": ("if ge get st 5 32", "if ge get st 5 31"),
    "members": ("if ge get t add b 5 512", "if ge get t add b 5 514"),
    "integer": ("if gt v div sub ulong 18446744073709551615 c 10", "if ge v div sub ulong 18446744073709551615 c 10"),
    "html": ("or eq v 60 or eq v 62", "or eq v 61 or eq v 62"),
}
for name, (old, new) in mutants.items():
    assert old in SOURCE, name
    mutant = build(SOURCE.replace(old, new, 1), "mutant-" + name)
    status, _, rc = execute(mutant, data, expected)
    assert status == "mismatch", (name, status, rc)
    print(f"json: completed-result mutant {name} detected PASS")
trap_source = SOURCE.replace("if jsondupe t d id\nret 5", "if jsondupe t d id\ntrap 5", 1)
trap = build(trap_source, "mutant-trap")
status, _, rc = execute(trap, data, expected)
assert status == "abnormal" and rc == 105, (status, rc)
print("json: trapping mutant rejected by harness PASS")
print(f"json: differential {len(rows)}/{len(rows)} PASS")
print(f"json: compiler sha256 {hashlib.sha256(OMC.read_bytes()).hexdigest()}")
