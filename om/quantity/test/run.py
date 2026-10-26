#!/usr/bin/env python3
"""Native contract test for om/quantity. Python compiles and compares; the checks are Omega."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
UNIT = ROOT / "om/quantity"
OUT = ROOT / "build/quantity"
COMPILER = subprocess.check_output([str(ROOT / "tools/omc.sh")], text=True).strip()

source = (UNIT / "quantity.om").read_text() + "\n" + (UNIT / "test/driver.om").read_text()
result = subprocess.run([COMPILER], input=source.encode(), capture_output=True)
if result.returncode:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "driver.om").write_text(source)
    sys.exit(f"quantity: compile failed: {result.stderr.decode()}")
OUT.mkdir(parents=True, exist_ok=True)
binary = OUT / "driver"
binary.write_bytes(result.stdout)
binary.chmod(0o700)
run = subprocess.run([str(binary)], capture_output=True, timeout=120)
if run.returncode != 0:
    sys.exit(f"quantity: driver exit {run.returncode}: {run.stderr.decode()}")
if run.stdout != bytes([0]):
    sys.exit(f"quantity: contract case {run.stdout[0]} failed (0 means every case passed)")
print("PASS quantity: checked-quantity contract cases, refusal leaves output unchanged")
