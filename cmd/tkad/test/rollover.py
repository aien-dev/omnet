#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time

root, binary = map(pathlib.Path, sys.argv[1:])
source = pathlib.Path(str(binary) + ".om").read_text()
needle = "fn dsbatch fd int to void\nfor i ulong 100000"
assert source.count(needle) == 1
omc = subprocess.check_output(["sh", str(root / "tools/omc.sh")], text=True).strip()
built = subprocess.run([omc], input=source.replace(needle, needle.replace("100000", "2")).encode(), capture_output=True)
assert built.returncode == 0, built.stderr.decode()
epoch = root / "build/tkad-epoch2"
epoch.write_bytes(built.stdout); epoch.chmod(0o700)
frame = struct.pack("<4sBBHQI", b"TKA\x01", 11, 1, 0, 0, 2) + b"{}"


def exact(s, n):
    out = b""
    while len(out) < n:
        v = s.recv(n-len(out))
        assert v, "truncated rollover reply"
        out += v
    return out


def response(s):
    magic, status, reserved, n = struct.unpack("<4sHHI", exact(s, 12))
    assert magic == b"TKA\x01" and status == 200 and reserved == 0
    result = json.loads(exact(s, n)); s.close()
    assert result == {"TKAInfo":None,"Revision":0,"Nodes":[]}, result


with tempfile.TemporaryDirectory(prefix="tkad-rollover-") as name:
    path = pathlib.Path(name)
    p = subprocess.Popen([str(epoch), name, "--init"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic()+10
        while not (path/"tkad.sock").exists():
            assert p.poll() is None, p.communicate()
            assert time.monotonic() < deadline
            time.sleep(.01)
        pid = p.pid
        # Connect both before sending the first request. The next connection is
        # queued while the epoch boundary exec replaces the process image.
        for _ in range(8):
            a = socket.socket(socket.AF_UNIX); a.settimeout(10); a.connect(str(path/"tkad.sock"))
            b = socket.socket(socket.AF_UNIX); b.settimeout(10); b.connect(str(path/"tkad.sock"))
            a.sendall(frame); b.sendall(frame)
            response(a); response(b)
            assert p.pid == pid and p.poll() is None
        link = os.readlink(f"/proc/{pid}/fd/66")
        for _ in range(4):
            s = socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(str(path/"tkad.sock"));s.sendall(frame);response(s)
        assert os.readlink(f"/proc/{pid}/fd/66") == link, "listener replaced"
        contender = subprocess.run([str(binary),name],capture_output=True,timeout=10)
        assert contender.returncode == 73, (contender.returncode,contender.stderr)
    finally:
        p.kill();p.communicate(timeout=10)
    missing = subprocess.run([str(epoch),"--resume"],capture_output=True,timeout=10)
    assert missing.returncode == 73
    directory = os.open(name,os.O_RDONLY|os.O_DIRECTORY)
    wrong = socket.socket(socket.AF_UNIX);wrong.bind("\0tkad-invalid-resume-"+str(os.getpid()))
    def swapped():
        os.dup2(wrong.fileno(),64,inheritable=True)
        os.dup2(directory,65,inheritable=True)
    bad = subprocess.run([str(epoch),"--resume"],preexec_fn=swapped,close_fds=False,capture_output=True,timeout=10)
    assert bad.returncode == 73
    wrong.close();os.close(directory)
print("PASS tkad epoch2 self-exec: queued clients, stable PID/listener, retained exclusion, missing/swapped FD refusal")
