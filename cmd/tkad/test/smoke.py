#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real AF_UNIX tests: no production backend or protocol mocks."""
import base64
import json
import os
import pathlib
import resource
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

BIN = pathlib.Path(sys.argv[1]).resolve()
FIX = json.loads(pathlib.Path(__file__).with_name("fixture.json").read_text())
PROBE = "--probe" in sys.argv
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
    def __init__(self, directory, initialize=False, file_limit=None):
        self.directory = pathlib.Path(directory)
        self.path = str(self.directory / "tkad.sock")
        def limits():
            if file_limit is not None:
                signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
                resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
        self.p = subprocess.Popen([str(BIN), str(self.directory)] + (["--init"] if initialize else []), stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=limits)
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

    def rpc(self, route, body=None, node=1, admin=False, expected=200, raw=None):
        payload = raw if raw is not None else json.dumps(body or {}, separators=(",", ":")).encode()
        frame = struct.pack("<4sBBHQI", b"TKA\x01", route, int(admin), 0, node, len(payload)) + payload
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(30)
            s.connect(self.path)
            s.sendall(frame)
            magic, status, reserved, size = struct.unpack("<4sHHI", exact(s, 12))
            check(magic == b"TKA\x01" and reserved == 0 and size <= 65536, "reply header")
            answer = json.loads(exact(s, size))
        check(status == expected, f"route {route}: expected {expected}, got {status}: {answer}")
        check(self.p.poll() is None, "daemon trapped/exited")
        return answer

    def req(self, **fields):
        return dict(Version=131, NodeKey=FIX["nodes"][0], **fields)

    def register(self, index, **kwargs):
        return self.rpc(9, dict(NodeID=index + 1, NodeKey=FIX["nodes"][index], RotationPubkey=FIX["rotations"][index], **kwargs), node=0, admin=True)

    def map(self):
        return self.rpc(11, node=0, admin=True)


def refused_start(directory, *args):
    p = subprocess.run([str(BIN), str(directory), *args], capture_output=True, timeout=20)
    check(p.returncode != 0 and not 100 <= p.returncode <= 114, f"startup must refuse normally, rc={p.returncode}")


def enable(d):
    d.register(0)
    d.register(1)
    ans = d.rpc(1, d.req(GenesisAUM=FIX["genesis"]), admin=True)
    check([v["NodeID"] for v in ans["NeedSignatures"]] == [1, 2], "complete frozen roster")
    check(ans["NeedSignatures"][1]["RotationPubkey"] == FIX["rotations"][1], "rotation public key")
    d.rpc(2, d.req(Signatures={"1": FIX["signatures"][0], "2": FIX["signatures"][1]}, SupportDisablement=FIX["secret"]), admin=True)


with tempfile.TemporaryDirectory(prefix="omnet-tkad-") as top:
    root = pathlib.Path(top)
    state = root / "state"
    state.mkdir(mode=0o700)
    d = Daemon(state, True)
    try:
        d.register(0)
        if PROBE:
            # A completed-result mutant must return a different result, not trap.
            d.rpc(1, d.req(GenesisAUM=FIX["genesis"]), expected=403)
            print("PASS tkad authorization probe")
            sys.exit(0)
        refused_start(state)
        refused_start(state, "--init")
        d.rpc(11, admin=False, expected=403)
        d.rpc(3, d.req(), expected=409)
        d.rpc(1, d.req(GenesisAUM=FIX["genesis"]), expected=403)
        d.rpc(1, d.req(GenesisAUM=FIX["genesis"]), node=99, admin=True, expected=403)
        d.rpc(1, dict(Version=131, NodeKey=FIX["nodes"][1], GenesisAUM=FIX["genesis"]), admin=True, expected=403)
        d.rpc(1, d.req(GenesisAUM="AA=="), admin=True, expected=400)
        d.register(1)
        before = d.map()
        begin = d.rpc(1, d.req(GenesisAUM=FIX["genesis"]), admin=True)
        check(len(begin["NeedSignatures"]) == 2, "begin roster")
        check(d.map()["TKAInfo"] is None, "pending genesis invisible")
        d.rpc(2, dict(Version=131, NodeKey=FIX["nodes"][1], Signatures={"1":FIX["signatures"][0],"2":FIX["signatures"][1]}), node=2, admin=True, expected=409)
        d.rpc(2, d.req(Signatures={"1":FIX["signatures"][0]}), admin=True, expected=409)
        d.rpc(2, d.req(Signatures={"1":FIX["signatures"][1],"2":FIX["signatures"][1]}), admin=True, expected=400)
        d.rpc(2, d.req(Signatures={"1":FIX["signatures"][0],"01":FIX["signatures"][0]}), admin=True, expected=400)
        d.rpc(2, d.req(Signatures={"9223372036854775808":FIX["signatures"][0],"2":FIX["signatures"][1]}), admin=True, expected=400)
        d.rpc(2, d.req(Signatures={"-0":FIX["signatures"][0],"2":FIX["signatures"][1]}), admin=True, expected=409)
        d.stop(); d = Daemon(state)
        check(d.map()["TKAInfo"] is None, "pending recovered but invisible")
        d.register(1)  # Any roster update invalidates pending init, even same bytes.
        d.rpc(2, d.req(Signatures={"1":FIX["signatures"][0],"2":FIX["signatures"][1]}), admin=True, expected=409)
        d.rpc(1, d.req(GenesisAUM=FIX["genesis"]), admin=True)
        d.rpc(2, d.req(Signatures={"01":FIX["signatures"][0],"+2":FIX["signatures"][1]}, SupportDisablement=FIX["secret"]), admin=True)
        check(d.map()["TKAInfo"] == {"Head":FIX["head"]}, "active map info")
        boot = d.rpc(3, d.req(Head=""))
        check(boot == {"GenesisAUM":FIX["genesis"]}, "bootstrap exact omission")
        alias = d.req(Head=""); alias["NodeKey"] = alias.pop("NodeKey")
        check(d.rpc(3, alias) == boot, "Go Kelvin-sign field fold")
        duplicate = d.req(Head=""); duplicate["NodeKey"] = FIX["nodes"][0]
        d.rpc(3, duplicate, expected=400)
        d.rpc(5, d.req(Head=FIX["head"], **{"MiſſingAUMs": []}))
        d.rpc(5, d.req(Head=FIX["head"], MissingAUMs=[], **{"MiſſingAUMs": []}), expected=400)
        d.rpc(4, d.req(Head=FIX["head"], Ancestors=[]))
        d.rpc(5, d.req(Head=FIX["updatedHead"], MissingAUMs=[FIX["update"]], Interactive=True))
        offer = d.rpc(4, d.req(Head=FIX["head"], Ancestors=[]))
        check(offer["Head"] == FIX["updatedHead"] and offer["MissingAUMs"] == [FIX["update"]], "sync missing real AUM")
        d.rpc(5, d.req(Head=FIX["updatedHead"], MissingAUMs=["AA=="], Interactive=False), expected=400)
        check(d.map()["TKAInfo"]["Head"] == FIX["updatedHead"], "bad batch atomic")
        d.register(2)
        d.rpc(7, d.req(Signature=FIX["signatures"][2]))
        check(d.map()["Nodes"][2]["KeySignature"] == FIX["signatures"][2], "sign caller differs from target")
        bad = bytearray(base64.b64decode(FIX["signatures"][2])); bad[-1] ^= 1
        d.rpc(7, d.req(Signature=base64.b64encode(bad).decode()), expected=403)
        affected = d.rpc(8, d.req(KeyID=FIX["keyID"]))
        check(affected["Signatures"] == FIX["signatures"], "affected raw signature array")
        # A replay of an already-retained AUM appends nothing, so it must not
        # persist: the snapshot bytes and Revision stay identical. The daemon
        # rewrote the snapshot here with Revision+1 before this was pinned.
        # File layout: 16-byte store magic, 40-byte record frame, then the
        # 16-word daemon header (word 6 Revision, word 15 the complete marker).
        def snapshot_state():
            raw = (state / "snapshot").read_bytes()
            check(raw[:16] == b"OMNETSNAP0000001", "snapshot store magic")
            header = struct.unpack_from("<16Q", raw, 56)
            check(header[15] == 1, "snapshot complete marker")
            return header[6], raw
        d.rpc(5, d.req(Head=FIX["emptyHead"], MissingAUMs=[FIX["emptyMeta"]], Interactive=True))
        revision, before_bytes = snapshot_state()
        replay = d.rpc(5, d.req(Head=FIX["emptyHead"], MissingAUMs=[FIX["emptyMeta"]], Interactive=True))
        check(replay == {"Head": FIX["emptyHead"]}, f"retained replay reply: {replay}")
        after_revision, after_bytes = snapshot_state()
        check(after_revision == revision, f"retained replay must not advance Revision: {revision} -> {after_revision}")
        check(after_bytes == before_bytes, "retained replay must not rewrite the snapshot")
        snapshot_map = d.map()
        d.stop(); d = Daemon(state)
        check(d.map() == snapshot_map, "typed empty metadata replay and signatures")
        d.rpc(5, d.req(Head=FIX["removedHead"], MissingAUMs=[FIX["removal"]], Interactive=True))
        d.rpc(7, d.req(Signature=FIX["signatures"][2]), expected=403)
        d.stop(); d = Daemon(state)
        check(d.map()["TKAInfo"]["Head"] == FIX["removedHead"], "revoked historical signatures recover")
        d.rpc(7, d.req(Signature=FIX["goodSignatures"][2]))
        d.rpc(6, d.req(Head=FIX["removedHead"], DisablementSecret=FIX["secret"]), expected=403)
        d.rpc(6, d.req(Head=FIX["head"], DisablementSecret=FIX["secret"]), admin=True, expected=409)
        d.rpc(6, d.req(Head=FIX["removedHead"], DisablementSecret="AA=="), admin=True, expected=403)
        d.rpc(3, raw=b'{"NodeKey":"x","NodeKey":"y"}', expected=400)
        duplicate = json.dumps(d.req()).encode()[:-1] + b',"nodekey":"x"}'
        d.rpc(3, raw=duplicate, expected=400)
        d.rpc(3, raw=b'{', expected=400)
        d.rpc(250, {}, node=0, admin=True, expected=404)
        # Partial/oversized headers are isolated to their connection; later requests work.
        for frame in [b"TK", struct.pack("<4sBBHQI", b"TKA\x01", 3, 0, 0, 1, 65537), struct.pack("<4sBBHQI", b"TKA\x01", 3, 0, 0, 1, 5) + b"{"]:
            with socket.socket(socket.AF_UNIX) as s:
                s.connect(d.path); s.sendall(frame)
            d.map()
        with socket.socket(socket.AF_UNIX) as s:
            s.connect(d.path); s.sendall(b"T")
            time.sleep(3.2)
            d.map()
        # Pre-rename disk write error must preserve live state and durable state.
        stable = d.map()
        d.stop(); d = Daemon(state, file_limit=1)
        d.rpc(10, {"NodeID":3}, node=0, admin=True, expected=503)
        check(d.map() == stable, "disk failure cannot publish candidate")
        d.stop(); d = Daemon(state)
        check(d.map() == stable, "disk failure cannot change recovery")
        d.rpc(6, d.req(Head=FIX["removedHead"], DisablementSecret=FIX["secret"]), admin=True)
        check(d.map()["TKAInfo"] == {"Disabled":True}, "disabled info distinct from nil")
        check(d.rpc(3, d.req(Head=FIX["removedHead"])) == {"DisablementSecret":FIX["secret"]}, "disabled bootstrap secret only")
        disabled = d.map()
        d.stop(); d = Daemon(state)
        check(d.map() == disabled, "disablement survives restart")
        d.rpc(10, {"NodeID":3}, node=0, admin=True)
        check(len(d.map()["Nodes"]) == 2, "registry remove")
    finally:
        d.stop()
    # Corrupt snapshot is never interpreted as an empty fresh installation.
    snap = state / "snapshot"
    data = bytearray(snap.read_bytes()); data[len(data)//2] ^= 128; snap.write_bytes(data)
    refused_start(state)
    missing = root / "missing"; missing.mkdir(mode=0o700)
    refused_start(missing)
    insecure = root / "insecure"; insecure.mkdir(mode=0o755)
    refused_start(insecure, "--init")
    print(f"PASS tkad real socket {checks} assertions: 8 RPCs, registry/map, security, restart, disk failure, malformed framing")
