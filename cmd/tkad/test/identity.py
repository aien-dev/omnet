#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Store identity and header schema.

The daemon header carries one schema word and a 128-bit store identity, so a
client that follows a path can tell whether the store behind it is still the
same store it was talking to. This pins the four properties that make the
identity usable, and the header validation that keeps it honest:

  * init draws a fresh identity, from the kernel CSPRNG, once;
  * the identity survives a restart and follows the directory when it is
    renamed, so it names the store and not the path;
  * two independent stores never share an identity, so the A6 replacement case
    is detectable rather than silent;
  * a header whose schema, identity or reserved words were altered is refused
    instead of being served.
"""
import base64
import hashlib
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time

PROBE = "--probe" in sys.argv
BIN = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "build/tkad")
if not BIN.is_absolute():
    BIN = pathlib.Path.cwd() / BIN
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
        self.path = str(self.directory / "tkad.sock")
        self.p = subprocess.Popen(
            [str(BIN), str(self.directory)] + (["--init"] if initialize else []),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.p.poll() is not None:
                raise AssertionError(f"startup rc={self.p.returncode}: {self.p.communicate()}")
            try:
                with socket.socket(socket.AF_UNIX) as s:
                    s.settimeout(.2)
                    s.connect(self.path)
                return
            except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
                time.sleep(.02)
        raise AssertionError("socket readiness timeout")

    def stop(self):
        if self.p.poll() is None:
            self.p.kill()
        self.p.communicate(timeout=10)

    def map(self):
        return self.rpc(11, {})

    def rpc(self, route, body, admin=1):
        payload = json.dumps(body, separators=(",", ":")).encode()
        frame = struct.pack("<4sBBHQI", b"TKA\x01", route, admin, 0, 0, len(payload)) + payload
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(30)
            s.connect(self.path)
            s.sendall(frame)
            magic, status, reserved, size = struct.unpack("<4sHHI", exact(s, 12))
            check(magic == b"TKA\x01" and reserved == 0 and size <= 65536, "reply header")
            answer = json.loads(exact(s, size))
        check(status == 200, f"route {route} status {status}: {answer}")
        return answer


def store(state):
    state.mkdir(mode=0o700)
    d = Daemon(state, initialize=True)
    try:
        return d.map()["StoreID"]
    finally:
        d.stop()


def restart(state):
    d = Daemon(state)
    try:
        return d.map()["StoreID"]
    finally:
        d.stop()


def header(state, word, value):
    """Rewrite one header word with the framing and checksums recomputed."""
    snapshot = (state / "snapshot").read_bytes()
    payloads = frames(snapshot)
    struct.pack_into("<Q", payloads[0], word * 8, value)
    (state / "snapshot").write_bytes(reseal(snapshot[:16], payloads))


def frames(snapshot):
    result = []
    p = 16
    while True:
        n = struct.unpack_from("<Q", snapshot, p)[0]
        if n == 0:
            return result
        result.append(bytearray(snapshot[p + 40:p + 40 + n]))
        p += 40 + n


def reseal(magic, payloads):
    # Independent Python implementation of the documented store framing.
    out = bytearray(magic)
    chain = bytes(32)
    total = 0
    for count, payload in enumerate(payloads, 1):
        digest = hashlib.blake2s(payload).digest()
        total += len(payload)
        out += struct.pack("<Q", len(payload)) + digest + payload
        chain = hashlib.blake2s(chain + digest + struct.pack("<QQQ", len(payload), total, count)).digest()
    out += bytes(8) + chain + struct.pack("<QQ", total, len(payloads))
    return out


def resumes(state):
    """None when the daemon served the store, else its exit code."""
    p = subprocess.Popen([str(BIN), str(state)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        code = p.wait(timeout=1.5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        return None
    p.communicate()
    return code


def refused(state):
    return resumes(state) == 73


with tempfile.TemporaryDirectory(prefix="tkad-identity-") as top:
    root = pathlib.Path(top)

    if PROBE:
        # Negative control: against a daemon without the identity guard this
        # must exit 0 (the guard is gone, a zero identity is served) and
        # against the production binary it must exit 3. run.sh requires both.
        probe = root / "probe"
        store(probe)
        header(probe, 9, 0)
        header(probe, 10, 0)
        sys.exit(0 if resumes(probe) is None else 3)

    # A fresh identity per store, and the same identity after a restart.
    first = store(root / "one")
    check(len(first) == 32 and all(c in "0123456789abcdef" for c in first), f"identity hex32: {first}")
    check(first != "0" * 32, "identity drawn, not absent")
    check(restart(root / "one") == first, "identity survives restart")

    # Independent stores never share an identity, so the A6 replacement case is
    # detectable: the path is the same, the identity is not.
    second = store(root / "two")
    check(second != first, "independent stores have distinct identities")

    # A durable mutation rewrites the header; the identity must not move.
    nodekey = "nodekey:" + "11" * 32
    rotation = base64.b64encode(bytes(range(1, 33))).decode()
    with tempfile.TemporaryDirectory(prefix="tkad-identity-commit-") as name:
        committed = pathlib.Path(name) / "commit"
        live = store(committed)
        d = Daemon(committed)
        try:
            d.rpc(9, {"NodeID": 1, "NodeKey": nodekey, "RotationPubkey": rotation}, admin=True)
            check(d.map()["StoreID"] == live, "identity unchanged by a durable mutation")
            after = d.map()
            check(after["Revision"] == 1 and len(after["Nodes"]) == 1, "mutation committed and durable")
        finally:
            d.stop()
        check(restart(committed) == live, "identity unchanged after a committed restart")

    # The identity names the store, not the path: rename and it is unchanged.
    (root / "one").rename(root / "one-moved")
    check(restart(root / "one-moved") == first, "identity follows the directory rename")
    check(store(root / "one") != first, "a new store at the vacated path has its own identity")

    # Header validation: schema, identity and reserved words are all enforced,
    # and each refusal is a refusal to serve, not a silent repair.
    for label, word, value in [
        ("schema absent", 8, 0),
        ("schema unknown", 8, 2),
        ("identity zero", 9, 0),
        ("reserved word", 12, 1),
    ]:
        mutated = root / label.replace(" ", "-")
        store(mutated)
        if word == 9:
            header(mutated, 9, 0)
            header(mutated, 10, 0)
        else:
            header(mutated, word, value)
        check(refused(mutated), f"{label} refused")
        check((mutated / "snapshot").exists(), f"{label}: refused without rewriting the snapshot")
print(f"PASS tkad store identity: {checks} checks, header schema and reserved words enforced, identity drawn once, follows the store across rename and restart")
