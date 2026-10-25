#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Directory replacement after open: the held descriptor, not the path, is the store."""
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time

BIN = pathlib.Path(sys.argv[1]).resolve()
FIX = json.loads(pathlib.Path(__file__).with_name("fixture.json").read_text())
checks = 0


def check(value, message):
    global checks
    assert value, message
    checks += 1


def exact(sock, count):
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise AssertionError("truncated daemon reply")
        result += part
    return result


class Daemon:
    def __init__(self, directory, initialize=False):
        self.directory = pathlib.Path(directory)
        self.p = subprocess.Popen([str(BIN), str(self.directory)] + (["--init"] if initialize else []),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.p.poll() is not None:
                raise AssertionError(f"startup rc={self.p.returncode}: {self.p.communicate()}")
            try:
                with socket.socket(socket.AF_UNIX) as s:
                    s.settimeout(.2)
                    s.connect(str(self.directory / "tkad.sock"))
                return
            except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
                time.sleep(.02)
        raise AssertionError("socket readiness timeout")

    def stop(self):
        if self.p.poll() is None:
            self.p.kill()
        return self.p.communicate(timeout=10)

    def rpc(self, route, body=None, node=1, admin=False, expected=200):
        payload = json.dumps(body or {}, separators=(",", ":")).encode()
        frame = struct.pack("<4sBBHQI", b"TKA\x01", route, int(admin), 0, node, len(payload)) + payload
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(30)
            s.connect(str(self.directory / "tkad.sock"))
            s.sendall(frame)
            magic, status, reserved, size = struct.unpack("<4sHHI", exact(s, 12))
            check(magic == b"TKA\x01" and reserved == 0 and size <= 65536, "reply header")
            answer = json.loads(exact(s, size))
        check(status == expected, f"route {route}: expected {expected}, got {status}: {answer}")
        check(self.p.poll() is None, "daemon trapped/exited")
        return answer

    def register(self, index):
        return self.rpc(9, dict(NodeID=index + 1, NodeKey=FIX["nodes"][index], RotationPubkey=FIX["rotations"][index]), node=0, admin=True)

    def revision(self):
        return self.rpc(11, node=0, admin=True)["Revision"]

    def storeid(self):
        return self.rpc(11, node=0, admin=True)["StoreID"]


def files(directory):
    return sorted(p.name for p in pathlib.Path(directory).iterdir())


def refused(directory):
    run = subprocess.run([str(BIN), str(directory)], capture_output=True, timeout=20)
    return run.returncode


with tempfile.TemporaryDirectory(prefix="tkad-replaced-") as top:
    live = pathlib.Path(top) / "store"
    live.mkdir(mode=0o700)
    moved = pathlib.Path(top) / "store-moved"       # where the opened directory went
    daemon = Daemon(live, initialize=True)
    try:
        daemon.register(0)
        check(daemon.revision() == 1, "first append committed")
        inode = os.stat(live).st_ino
        check("snapshot" in files(live), "snapshot on disk before replacement")

        # An unprivileged racer replaces the path with a fresh directory of the
        # same name while the daemon keeps its descriptor open.
        os.rename(live, moved)
        live.mkdir(mode=0o700)
        check(os.stat(live).st_ino != inode and os.stat(moved).st_ino == inode, "path now names a different directory")
        daemon.directory = moved
        check(os.path.realpath(f"/proc/{daemon.p.pid}/cwd") == os.path.realpath(moved), "daemon cwd is the opened directory")

        check(daemon.revision() == 1, "reads still served from the opened directory")
        daemon.register(1)
        check(daemon.revision() == 2, "append after replacement committed")
        check(files(live) == [], f"replacement directory untouched: {files(live)}")
        check("snapshot" in files(moved), "snapshot written beside the opened descriptor")

        # The held directory still excludes a second store on the inode, whatever
        # its path is now called.
        check(refused(moved) == 73, "exclusion follows the inode, not the path")
        # The replacement directory holds no store, so a resume there refuses
        # instead of serving a fresh empty revision as if it were this store.
        check(refused(live) == 73, "resume in the replacement directory refused")
        check(files(live) == [], "refused resume wrote nothing into the replacement")

        # The same path can host an unrelated store while the opened one is still
        # live. Its identity is what tells a reconnecting client that the path it
        # follows now names a different store.
        other = Daemon(live, initialize=True)
        try:
            check(other.revision() == 0, "replacement path accepted an independent empty store")
            check(other.storeid() != daemon.storeid(), "replacement store is distinguishable by identity")
        finally:
            other.stop()
    finally:
        daemon.stop()

    # Nothing was lost by the rename: the committed revision is still there.
    reopened = Daemon(moved)
    try:
        check(reopened.revision() == 2, "committed revision survives restart")
        check(files(moved).count("snapshot") == 1, "single snapshot after restart")
    finally:
        reopened.stop()
print(f"PASS tkad directory replacement: {checks} checks, commits land beside the opened descriptor, replacement stays empty and refuses resume")
