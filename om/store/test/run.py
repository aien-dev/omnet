#!/usr/bin/env python3
"""Native process tests. Python is an independent framing referee, never runtime logic."""
import errno
import hashlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
UNIT = ROOT / "om/store"
COMPILER = subprocess.check_output([str(ROOT / "tools/omc.sh")], text=True).strip()
BASE = (ROOT / "om/blake2s/blake2s.om").read_text()
QUANT = (ROOT / "om/quantity/quantity.om").read_text()
HELP = (UNIT / "store.om").read_text()
POOL = (UNIT / "storepool.om").read_text()
DRIVER = (UNIT / "test/driver.om").read_text()
RESUME = (UNIT / "test/resume.om").read_text()
COUNT = 0


def compile_binary(folder, name, helpers=HELP, pool=POOL, driver=DRIVER, prefix=""):
    source = QUANT + "\n" + BASE + "\n" + prefix + "\n" + helpers + "\n" + pool + "\n" + driver
    result = subprocess.run([COMPILER], input=source.encode(), capture_output=True)
    if result.returncode:
        (folder / (name + ".om")).write_text(source)
        raise AssertionError(f"compile {name}: {result.stderr.decode()}")
    target = folder / name
    target.write_bytes(result.stdout)
    target.chmod(0o700)
    return target


def call(binary, path, mode, expected=0, seed="a"):
    global COUNT
    r = subprocess.run([str(binary), str(path), mode, seed], capture_output=True, timeout=120)
    assert r.returncode == 0, (mode, "driver did not complete", r.returncode, r.stderr)
    assert r.stdout == bytes([expected]), (mode, r.stdout, expected, r.stderr)
    COUNT += 1


def directory(root, name):
    p = root / name
    p.mkdir(mode=0o700)
    return p


def frame(payloads):
    result = bytearray(b"OMNETSNAP0000001")
    chain = bytes(32)
    total = 0
    for count, payload in enumerate(payloads, 1):
        digest = hashlib.blake2s(payload).digest()
        total += len(payload)
        chain = hashlib.blake2s(chain + digest + struct.pack("<QQQ", len(payload), total, count)).digest()
        result.extend(struct.pack("<Q", len(payload)) + digest + payload)
    result.extend(struct.pack("<Q", 0) + chain + struct.pack("<QQ", total, len(payloads)))
    return bytes(result)


def save(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


def inherited_call(binary, first=None, second=None, arg="--resume", expected=b"\1"):
    global COUNT
    targets = []
    try:
        for target, source in ((64, first), (65, second)):
            try:
                os.fstat(target)
            except OSError as e:
                assert e.errno == errno.EBADF
            else:
                raise AssertionError("test handoff target already occupied")
            if source is not None:
                os.dup2(source, target, inheritable=True)
                targets.append(target)
        result = subprocess.run([str(binary), str(arg)], pass_fds=targets,
                                input=b"x", capture_output=True, timeout=20)
        assert result.returncode == 0 and result.stdout == expected, (
            "inheritance driver failed", result.returncode, result.stdout, result.stderr)
        COUNT += 1
    finally:
        for target in targets:
            os.close(target)


with tempfile.TemporaryDirectory(prefix="omnet-store-") as tmp:
    root = Path(tmp)
    binary = compile_binary(root, "store")
    for boundary in ("ret write fd b off n", "ret read fd b off n", "ret fsync fd",
                     "ret renames p ulong 0 ulong 26 int 0"):
        assert HELP.count(boundary) == 1, ("fault boundary drift", boundary)
    injected = HELP.replace("ret write fd b off n", """if eq get testfi 0 long 87
ret -5
end
if eq get testfi 0 long 90
ret 0
end
if eq get testfi 0 long 88
ret -4
end
if eq get testfi 0 long 74
if eq get testfi 2 long 0
put testfi 2 1
ret -4
end
end
if eq get testfi 0 long 80
if gt n 7
ret write fd b off ulong 7
end
end
ret write fd b off n""").replace("ret read fd b off n", """if eq get testfi 0 long 82
ret -5
end
if eq get testfi 0 long 86
ret 0
end
if eq get testfi 0 long 74
if eq get testfi 3 long 0
put testfi 3 1
ret -4
end
end
if eq get testfi 0 long 84
if gt n 7
ret read fd b off ulong 7
end
end
ret read fd b off n""").replace("ret fsync fd", """put testfi 1 add get testfi 1 long 1
if eq get testfi 0 long 70
ret -5
end
if eq get testfi 0 long 68
if eq get testfi 1 long 2
ret -5
end
end
ret fsync fd""").replace("ret renames p ulong 0 ulong 26 int 0", """if eq get testfi 0 long 78
ret -5
end
ret renames p ulong 0 ulong 26 int 0""")
    assert injected != HELP
    fault = compile_binary(root, "fault", helpers=injected,
                           prefix="global testfi long 4",
                           driver=DRIVER.replace("note TEST_ARM", "put testfi 0 long mode\nput testfi 1 0"))
    p = directory(root, "state")
    call(binary, p, "L", 1)
    call(binary, p, "I")
    original = (p / "snapshot").read_bytes()
    payload = bytes((ord("a") + i) & 255 for i in range(65536))
    assert original == frame([payload, b"a" * 17]), "independent framing mismatch"
    call(binary, p, "L")
    ident = p.stat()
    with socket.socket(socket.AF_UNIX) as guard:
        guard.bind(b"\0omnet.store.v1." + struct.pack("<QQ", ident.st_dev, ident.st_ino))
        call(binary, p, "S", 1)
    call(binary, p, "I", 1)
    call(binary, p, "A", seed="b")
    call(binary, p, "L")
    call(binary, p, "S", seed="b")
    call(binary, p, "L", seed="b")
    call(binary, p, "S")
    resume = compile_binary(root, "resume", driver=RESUME)
    rollover = subprocess.Popen([str(resume), str(p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        pid = rollover.pid
        assert rollover.stdout.read(2) == b"\x08\x09", "self-exec did not recover"
        assert rollover.pid == pid and rollover.poll() is None
        call(binary, p, "S", 1)
        rollover.stdin.write(b"x")
        rollover.stdin.flush()
        assert rollover.stdout.read(1) == b"\0"
        assert rollover.wait(timeout=5) == 0
        COUNT += 1
    finally:
        if rollover.poll() is None:
            rollover.kill()
            rollover.wait(timeout=5)
        rollover.stdin.close()
        rollover.stdout.close()
    call(binary, p, "L")
    partial_driver = RESUME.replace("if ne stpass 64 65 0\nret rsresult 1",
                                    "if ne stpass 64 2147483647 0\n"
                                    "if ne stbegin 1\nret rsresult 4\nend\n"
                                    "if ne stload 1\nret rsresult 4\nend\n"
                                    "ret rsresult 1")
    assert partial_driver != RESUME
    partial = compile_binary(root, "partial-handoff", driver=partial_driver)
    inherited_call(partial, arg=p)  # first dup succeeds, impossible second FD fails, fail-stop
    call(binary, p, "L")
    failed_driver = RESUME.replace("put p 4 47", "put p 4 120")
    assert failed_driver != RESUME
    failed_exec = compile_binary(root, "failed-exec", driver=failed_driver)
    inherited_call(failed_exec, arg=p, expected=b"\x08\x05")
    call(binary, p, "L")
    inherited_call(resume)  # missing descriptors
    otherdir = directory(root, "other-directory")
    dirfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY)
    otherfd = os.open(otherdir, os.O_RDONLY | os.O_DIRECTORY)
    filefd = os.open(p / "snapshot", os.O_RDONLY)
    try:
        inherited_call(resume, dirfd, None)
        inherited_call(resume, dirfd, filefd)  # non-socket lock
        inherited_call(resume, dirfd, None, arg=p)  # occupied first handoff target
        with socket.socket(socket.AF_UNIX) as guard:
            inherited_call(resume, dirfd, guard.fileno())  # unnamed socket
            guard.bind(b"\0omnet.store.v1." + struct.pack("<QQ", ident.st_dev, ident.st_ino))
            inherited_call(resume, guard.fileno(), dirfd)  # swapped resources
            inherited_call(resume, otherfd, guard.fileno())  # lock belongs to another directory
            inherited_call(resume, dirfd, guard.fileno(), expected=b"\x09\0")
        with socket.socket(socket.AF_UNIX) as guard:
            guard.bind(b"\0omnet.store.v1." + struct.pack("<QQ", ident.st_dev, ident.st_ino) + b"x")
            inherited_call(resume, dirfd, guard.fileno())  # full address length must match
    finally:
        os.close(dirfd)
        os.close(otherfd)
        os.close(filefd)

    # Lock key is directory identity, not the spelling of its path.
    holder = subprocess.Popen([str(binary), str(p), "H"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert holder.stdout.read(1) == b"\x09"
        aliases = [p, p / ".", root / "state/../state"]
        link = root / "parent-alias"
        link.symlink_to(root, target_is_directory=True)
        aliases.append(link / "state")  # trusted ancestor alias, final component is a directory
        for alias in aliases:
            call(binary, alias, "S", 1)
        save(p / "snapshot.tmp", b"stale")
        call(binary, p, "S", 1)
        assert (p / "snapshot.tmp").exists(), "contender removed owner's temporary file"
    finally:
        holder.kill()
        holder.wait(timeout=5)
        holder.stdin.close()
        holder.stdout.close()
    call(binary, p, "L")
    assert not (p / "snapshot.tmp").exists()
    # Kill a writer with real staged frames, not merely an invented stale file.
    holder = subprocess.Popen([str(binary), str(p), "K", "b"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert holder.stdout.read(1) == b"\x09"
        assert (p / "snapshot.tmp").stat().st_size > 65536
        call(binary, p, "S", 1)
    finally:
        holder.kill()
        holder.wait(timeout=5)
        holder.stdin.close()
        holder.stdout.close()
    call(binary, p, "L")
    assert (p / "snapshot").read_bytes() == original
    assert not (p / "snapshot.tmp").exists()

    # Only explicit init accepts absent committed state; orphan temp is never promoted.
    orphan = directory(root, "orphan")
    save(orphan / "snapshot.tmp", original)
    call(binary, orphan, "L", 1)
    assert (orphan / "snapshot.tmp").exists()
    call(binary, orphan, "I")
    empty = directory(root, "empty")
    call(binary, empty, "E")
    assert (empty / "snapshot").read_bytes() == frame([])
    call(binary, empty, "L", 3)  # framing accepts empty; driver expects nonempty semantic records
    call(binary, p, "U")  # too-large chunk is a declared error, not an array trap
    call(binary, p, "Q")  # exactly 65536 frames, then refuse one more
    call(binary, p, "C")  # exactly 32 MiB payload, then refuse one more byte
    call(binary, p, "Y")  # a negative running byte charge is a declared refusal, not a trap
    call(binary, p, "B")  # a negative running frame count is a declared refusal, not a trap
    assert (p / "snapshot").read_bytes() == original
    capacity = directory(root, "capacity")
    call(binary, capacity, "E")
    call(binary, capacity, "G")  # durable full-capacity snapshot and streaming recovery

    symlink = root / "dir-link"
    symlink.symlink_to(p, target_is_directory=True)
    call(binary, symlink, "L", 1)
    for mode in (0o755, 0o750, 0o1700):
        p.chmod(mode)
        call(binary, p, "L", 1)
    p.chmod(0o700)
    regular = root / "not-directory"
    save(regular, b"x")
    call(binary, regular, "L", 1)
    for name in ("snapshot", "snapshot.tmp"):
        target = p / name
        if target.exists():
            target.unlink()
        target.symlink_to(regular)
        call(binary, p, "L", 1)
        assert target.is_symlink()
        target.unlink()
        target.mkdir(mode=0o700)
        call(binary, p, "L", 1)
        target.rmdir()
        os.mkfifo(target, 0o600)
        call(binary, p, "L", 1)
        target.unlink()
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(target))
        call(binary, p, "L", 1)
        sock.close()
        target.unlink()
        save(target, original)
        for mode in (0o644, 0o400, 0o1600):
            target.chmod(mode)
            call(binary, p, "L", 1)
        target.chmod(0o600)
        other = root / "extra-link"
        os.link(target, other)
        call(binary, p, "L", 1)
        other.unlink()
        if os.geteuid() == 0:
            os.chown(target, 12345, -1)
            call(binary, p, "L", 1)
            os.chown(target, 0, -1)
        target.unlink()
        save(p / "snapshot", original)
    if os.geteuid() == 0:
        os.chown(p, 12345, -1)
        call(binary, p, "L", 1)
        os.chown(p, 0, -1)

    # Truncations span header, frames, payload and footer. Corruption includes every field class.
    for size in (0, 1, 15, 16, 23, 55, 56, 65591, 65592, len(original)-56, len(original)-1):
        save(p / "snapshot", original[:size])
        call(binary, p, "L", 1)
    for offset in (0, 15, 16, 20, 24, 55, 56, 1000, 65591, len(original)-49, len(original)-16, len(original)-1):
        broken = bytearray(original)
        broken[offset] ^= 1
        save(p / "snapshot", broken)
        call(binary, p, "L", 1)
    save(p / "snapshot", original + b"x")
    call(binary, p, "L", 1)
    save(p / "snapshot", original)
    # Oversize metadata rejected before reading attacker-controlled file contents.
    with (p / "snapshot").open("r+b") as f:
        f.truncate(36175945)
    call(binary, p, "L", 1)
    save(p / "snapshot", original)

    # Fault controls exist only in a separately compiled test image, never in store source.
    for mode in ("W", "Z", "R", "F", "N", "X", "V"):
        call(fault, p, mode, 1, seed="b")
        assert (p / "snapshot").read_bytes() == original, mode
        call(binary, p, "L")
    for mode in ("P", "T", "J"):
        call(fault, p, mode, seed="b")
        call(binary, p, "L", seed="b")
        call(binary, p, "S")
    call(fault, p, "D", 2, seed="b")
    call(binary, p, "L", seed="b")  # selected new snapshot, startup re-syncs it

    # Completed-result mutant: removing payload checksum comparison must be observable.
    mutant_pool = POOL.replace("if ne steqhash h 8 d 0", "if ne int 0 int 0")
    assert mutant_pool != POOL
    mutant = compile_binary(root, "mutant", pool=mutant_pool)
    # A payload mismatch still reaches semantic checking (3), rather than framing refusal (1).
    # Keep the original frame digest but forge the final chain for altered payload bytes.
    changed = bytearray(payload)
    changed[944] ^= 1
    forged = bytearray(frame([bytes(changed), b"a" * 17]))
    forged[24:56] = original[24:56]
    save(p / "snapshot", forged)
    call(binary, p, "L", 1)
    call(mutant, p, "L", 3)
    save(p / "snapshot", original)
    print(f"PASS store: {COUNT} completed native cases; independent BLAKE2s framing; checksum mutant detected")
    if os.geteuid() != 0:
        print("SKIP store foreign-UID chown fixtures: runner is non-root")
