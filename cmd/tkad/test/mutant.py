#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import pathlib
import subprocess
import sys

root, binary = map(pathlib.Path, sys.argv[1:])
source = pathlib.Path(str(binary) + ".om").read_text()
omc = subprocess.check_output(["sh", str(root / "tools/omc.sh")], text=True).strip()
needle = "fn dsbegin t view ulong 32768 d view uchar 65536 out edit uchar 65536 to int\nif eq get ds_ctl 3 0\nret 403\nend"
assert source.count(needle) == 1
variants = {
    "admin-bypass": needle.replace("if eq get ds_ctl 3 0", "if eq get ds_ctl 3 2"),
    "trap": needle.replace("ret 403", "trap 1"),
}
for label, replacement in variants.items():
    path = root / "build" / ("tkad-mutant-" + label)
    build = subprocess.run([omc], input=source.replace(needle, replacement).encode(), capture_output=True)
    assert build.returncode == 0, build.stderr.decode()
    path.write_bytes(build.stdout)
    path.chmod(0o700)
    run = subprocess.run([sys.executable, str(root / "cmd/tkad/test/smoke.py"), str(path), "--probe"], capture_output=True, text=True, timeout=60)
    completed_mismatch = run.returncode != 0 and "expected 403, got 200" in run.stderr
    if label == "admin-bypass":
        assert completed_mismatch, (run.returncode, run.stdout, run.stderr)
        print("PASS tkad completed-response admin-bypass mutant detected")
    else:
        assert run.returncode != 0 and not completed_mismatch and "truncated daemon reply" in run.stderr, (run.returncode, run.stdout, run.stderr)
        print("PASS tkad trapping mutant rejected, not counted as detection")
