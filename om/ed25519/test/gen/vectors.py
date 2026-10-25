# SPDX-License-Identifier: Apache-2.0
"""Regenerate the static vector files of om/ed25519/test/vectors/ (test tooling only).

Usage: python3 vectors.py SRC ORACLE OUT
  SRC     directory holding the pinned upstream files (pinned URLs in om/ed25519/README.md):
          rfc8032.txt, zip215_test.go, ed25519_test.json, and the upstream licenses
          ed25519consensus.LICENSE and wycheproof.LICENSE (copied verbatim to OUT as
          zip215.LICENSE and wycheproof.LICENSE; OUT/rfc8032.NOTICE is cut from the RFC's own
          Copyright Notice section)
  ORACLE  the Go referee built from gen/oracle (reads "PK SIG MSG" lines, prints "S C")
  OUT     output directory (om/ed25519/test/vectors)

Line format written (read by test/driver.om): ES EC PKHEX SIGHEX MSGHEX, ES/EC the expected strict
and consensus results (0, 1, or - to skip). Lines starting with # are comments.
"""
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def oracle(exe, cases):
    """cases: list of (pk, sig, msg) bytes; returns list of (strict, consensus) ints from Go."""
    data = "".join(f"{pk.hex()} {sig.hex()} {msg.hex()}\n" for pk, sig, msg in cases)
    out = subprocess.run([exe], input=data.encode(), capture_output=True, check=True).stdout
    res = [tuple(int(x) for x in line.split()) for line in out.decode().splitlines()]
    assert len(res) == len(cases)
    return res


def line(es, ec, pk, sig, msg):
    return f"{es} {ec} {pk.hex()} {sig.hex()} {msg.hex()}\n"


def flip(b, bit):
    a = bytearray(b)
    a[bit // 8] ^= 1 << (bit % 8)
    return bytes(a)


def rfc(src, exe, out):
    path = os.path.join(src, "rfc8032.txt")
    text = open(path).read().split("\n")
    start = text.index("7.1.  Test Vectors for Ed25519")
    end = text.index("7.2.  Test Vectors for Ed25519ctx")
    tests, cur, field = [], None, None
    for raw in text[start:end]:
        s = raw.strip()
        if raw.startswith("   -----TEST"):
            cur = {"name": s[10:], "PUBLIC KEY": "", "MESSAGE": "", "SIGNATURE": ""}
            tests.append(cur)
            field = None
            continue
        m = re.match(r"(SECRET KEY|PUBLIC KEY|MESSAGE|SIGNATURE)", s)
        if m:
            field = m.group(1)
            continue
        if s in ("ALGORITHM:", "Ed25519"):
            field = None
            continue
        if cur and field and field != "SECRET KEY" and re.fullmatch(r"[0-9a-f]+", s):
            cur[field] += s
    assert [t["name"] for t in tests] == ["1", "2", "3", "1024", "SHA(abc)"]
    cases, notes = [], []
    for t in tests:
        pk = bytes.fromhex(t["PUBLIC KEY"])
        sig = bytes.fromhex(t["SIGNATURE"])
        msg = bytes.fromhex(t["MESSAGE"])
        cases.append((pk, sig, msg, 1, f"TEST {t['name']} ({len(msg)}-byte message)"))
        # one flipped bit in R, in S, in the public key, and (if nonempty) in the message
        cases.append((pk, flip(sig, 3), msg, 0, f"TEST {t['name']} R bit 3 flipped"))
        cases.append((pk, flip(sig, 256 + 9), msg, 0, f"TEST {t['name']} S bit 9 flipped"))
        cases.append((flip(pk, 17), sig, msg, 0, f"TEST {t['name']} public key bit 17 flipped"))
        if msg:
            cases.append((pk, sig, flip(msg, 8 * len(msg) - 1), 0,
                          f"TEST {t['name']} last message bit flipped"))
    go = oracle(exe, [c[:3] for c in cases])
    with open(os.path.join(out, "rfc8032.txt"), "w") as f:
        f.write("# RFC 8032 section 7.1 Ed25519 test vectors (TEST 1, 2, 3, 1024, SHA(abc)) and\n")
        f.write("# one-bit-flipped variants. Source: https://www.rfc-editor.org/rfc/rfc8032.txt\n")
        f.write(f"# sha256 {sha256(path)}. Expected: 1 for the RFC vectors, 0 for every flip\n")
        f.write("# (Go crypto/ed25519 and ed25519consensus agree on every line).\n")
        f.write("# Keys, messages and signatures are from RFC 8032, Copyright (c) 2017 IETF Trust and the\n")
        f.write("# persons identified as the document authors (S. Josefsson, I. Liusvaara); see\n")
        f.write("# rfc8032.NOTICE. Converted to this line format (and bit flips added) by gen/vectors.py.\n")
        for (pk, sig, msg, exp, name), g in zip(cases, go):
            assert g == (exp, exp), (name, g)
            f.write(f"# {name}\n")
            f.write(line(exp, exp, pk, sig, msg))
    return len(cases)


def zip215(src, exe, out):
    path = os.path.join(src, "zip215_test.go")
    body = open(path).read()
    pairs = re.findall(r'\{\s*"([0-9a-f]{64})",\s*"([0-9a-f]{128})",\s*\}', body)
    assert len(pairs) == 196, len(pairs)
    msg = b"Zcash"
    cases = [(bytes.fromhex(a), bytes.fromhex(b), msg) for a, b in pairs]
    go = oracle(exe, cases)
    ns = sum(g[0] for g in go)
    with open(os.path.join(out, "zip215.txt"), "w") as f:
        f.write("# ZIP 215 small-order / non-canonical cases, message \"Zcash\" (196 = 14 A x 14 R\n")
        f.write("# encodings, S = 0). Source: github.com/hdevalence/ed25519consensus zip215_test.go at\n")
        f.write("# commit 15731de461e4d21d6a79d5b7aaf473454f9d2009 (tag v0.2.0),\n")
        f.write(f"# sha256 {sha256(path)}. Consensus expected 1 for all 196 (TestZIP215).\n")
        f.write("# Strict expected = Go 1.26.0 crypto/ed25519.Verify, run as referee "
                f"({ns} of 196 accepted).\n")
        f.write("# The key and signature hex strings are copied from that file (header: Copyright 2016\n")
        f.write("# Henry de Valence. All rights reserved. Use of this source code is governed by a\n")
        f.write("# BSD-style license). Redistributed under that license, included verbatim as\n")
        f.write("# zip215.LICENSE (Copyright (c) 2009 The Go Authors; Copyright (c) 2020 Henry de\n")
        f.write("# Valence). Converted to this line format by gen/vectors.py.\n")
        for (pk, sig, m), g in zip(cases, go):
            assert g[1] == 1
            f.write(line(g[0], 1, pk, sig, m))
    return len(cases), ns


def wycheproof(src, exe, out):
    path = os.path.join(src, "ed25519_test.json")
    d = json.load(open(path))
    cases, skipped = [], []
    for g in d["testGroups"]:
        pk = bytes.fromhex(g["publicKey"]["pk"])
        for t in g["tests"]:
            sig = bytes.fromhex(t["sig"])
            msg = bytes.fromhex(t["msg"])
            if len(sig) != 64:
                assert t["result"] == "invalid"
                skipped.append(t["tcId"])
                continue
            cases.append((pk, sig, msg, t))
    go = oracle(exe, [c[:3] for c in cases])
    acc = []
    with open(os.path.join(out, "wycheproof.txt"), "w") as f:
        f.write("# Wycheproof ed25519_test.json, https://github.com/C2SP/wycheproof/blob/\n")
        f.write("# a3d5d1423f2592d6646836a45a21a1b209da9f4d/testvectors_v1/ed25519_test.json\n")
        f.write(f"# sha256 {sha256(path)}. Strict expected = Wycheproof result for valid/invalid\n")
        f.write("# (Go 1.26.0 crypto/ed25519 agrees on each), and Go's result for 'acceptable'.\n")
        f.write("# Consensus expected = ed25519consensus v0.2.0 run as referee. Signatures that are not\n")
        f.write(f"# 64 bytes long cannot be passed to edverify (tcId {', '.join(map(str, skipped))};\n")
        f.write("# all 'invalid'; Go rejects them by length).\n")
        f.write("# Copyright 2016-2026 The Wycheproof Authors, licensed under the Apache License 2.0\n")
        f.write("# (wycheproof.LICENSE, upstream LICENSE verbatim). Modified: converted from JSON to\n")
        f.write("# this line format by gen/vectors.py; tests with signatures not 64 bytes left out.\n")
        for (pk, sig, msg, t), g in zip(cases, go):
            if t["result"] == "valid":
                assert g[0] == 1, t["tcId"]
            elif t["result"] == "invalid":
                assert g[0] == 0, t["tcId"]
            else:
                acc.append((t["tcId"], g[0], g[1]))
            f.write(f"# tcId {t['tcId']} {t['result']} {' '.join(t['flags'])}\n")
            f.write(line(g[0], g[1], pk, sig, msg))
    return len(cases), skipped, acc


def edge(exe, out):
    """Go-refereed edge corpus: signatures from the pure-Python RFC 8032 signer below (seed fixed),
    pushed to the corners where strict and consensus differ."""
    rnd = random.Random(20261025)
    small = small_order_encodings()
    cases = []
    for i in range(400):
        sk = rnd.randbytes(32)
        msg = rnd.randbytes(rnd.randrange(0, 200))
        kind = i % 8
        if kind == 1:  # R + small-order point, hashed as sent: consensus accepts, strict rejects
            pk, sig = sign(sk, msg, tr=rnd.randrange(1, 8))
        elif kind == 2:  # A + small-order point: consensus accepts, strict iff [k]T = 0
            pk, sig = sign(sk, msg, ta=rnd.randrange(1, 8))
        elif kind == 3:  # both torsioned
            pk, sig = sign(sk, msg, tr=rnd.randrange(1, 8), ta=rnd.randrange(1, 8))
        else:
            pk, sig = sign(sk, msg)
        if kind == 0:  # S + L (S >= L is rejected in both modes)
            s = int.from_bytes(sig[32:], "little") + L
            sig = sig[:32] + s.to_bytes(32, "little")
        elif kind == 4:  # small-order A and R (canonical or not), S = 0, random message
            pk = rnd.choice(small)
            sig = rnd.choice(small) + bytes(32)
        elif kind == 5:  # random 32 bytes as A
            pk = rnd.randbytes(32)
        elif kind == 6:  # random 32 bytes as R
            sig = rnd.randbytes(32) + sig[32:]
        elif kind == 7:  # one of the top three bits of S set
            sig = sig[:63] + bytes([sig[63] | (32 << rnd.randrange(0, 3))])
        cases.append((pk, sig, msg))
    go = oracle(exe, cases)
    with open(os.path.join(out, "edge.txt"), "w") as f:
        f.write("# Edge corpus (400 cases, generated by gen/vectors.py, seed 20261025): RFC 8032\n")
        f.write("# signatures with S + L, torsioned R and/or A (hashed as sent), small-order A and R\n")
        f.write("# with S = 0, random A or R bytes, high S bits. Expected = Go 1.26.0\n")
        f.write("# crypto/ed25519.Verify (strict) and ed25519consensus v0.2.0 (consensus), run as referees.\n")
        for (pk, sig, msg), g in zip(cases, go):
            f.write(line(g[0], g[1], pk, sig, msg))
    return len(cases), sum(g[0] for g in go), sum(g[1] for g in go)


# --- pure-Python Ed25519 reference (RFC 8032 section 5.1, test-time generator only) ---
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def padd(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def pmul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = padd(q, p)
        p = padd(p, p)
        s >>= 1
    return q


def penc(p):
    x, y, z, _ = p
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def pdec(b):
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    y %= P
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    if v * x * x % P == u:
        pass
    elif v * x * x % P == (-u) % P:
        x = x * I % P
    else:
        return None
    if (x & 1) != sign:
        x = (-x) % P
    return (x, y, 1, x * y % P)


BY = 4 * pow(5, P - 2, P) % P
BASE = pdec(BY.to_bytes(32, "little"))


def sign(sk, msg, tr=0, ta=0):
    """RFC 8032 section 5.1.6 signing; tr/ta add [tr]T / [ta]T (T of order 8) to R / A before
    they are encoded and hashed, so the cofactored equation still holds."""
    h = hashlib.sha512(sk).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pk = penc(padd(pmul(a, BASE), pmul(ta, T8)))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % L
    rb = penc(padd(pmul(r, BASE), pmul(tr, T8)))
    k = int.from_bytes(hashlib.sha512(rb + pk + msg).digest(), "little") % L
    s = (r + k * a) % L
    return pk, rb + s.to_bytes(32, "little")


def torsion8():
    """A point of order 8: [L]Q for the first decodable small y whose [4][L]Q is not the identity."""
    ident = penc((0, 1, 1, 0))
    for y in range(2, 1000):
        q = pdec(y.to_bytes(32, "little"))
        if q is None:
            continue
        t = pmul(L, q)
        if penc(pmul(4, t)) != ident:
            return t
    raise AssertionError("no point of order 8 found")


T8 = torsion8()


def small_order_encodings():
    """The 8 small-order points (canonical encodings), their non-canonical y + p forms where
    y + p < 2^255, and x = 0 points with the sign bit set."""
    out = [penc(pmul(k, T8)) for k in range(8)]
    extra = []
    for e in out:
        v = int.from_bytes(e, "little")
        y = v & ((1 << 255) - 1)
        if y + P < 2**255:
            extra.append(((y + P) | (v >> 255 << 255)).to_bytes(32, "little"))
        if y in (1, P - 1):  # x = 0 points: set the sign bit too
            extra.append((y | (1 << 255)).to_bytes(32, "little"))
    return out + extra


def notices(src, out):
    """Third-party notices that must travel with the copied vectors."""
    for name, dst in (("ed25519consensus.LICENSE", "zip215.LICENSE"),
                      ("wycheproof.LICENSE", "wycheproof.LICENSE")):
        shutil.copyfile(os.path.join(src, name), os.path.join(out, dst))
    text = open(os.path.join(src, "rfc8032.txt")).read().split("\n")
    a = text.index("Copyright Notice")
    b = next(i for i in range(a + 1, len(text)) if text[i - 1].strip().endswith("to this document."))
    with open(os.path.join(out, "rfc8032.NOTICE"), "w") as f:
        f.write("The keys, messages and signatures in rfc8032.txt are copied from RFC 8032\n")
        f.write("(https://www.rfc-editor.org/rfc/rfc8032.txt), section 7.1. Its notice, verbatim:\n\n")
        f.write("\n".join(text[a:b]) + "\n")


def main():
    src, exe, out = sys.argv[1:4]
    os.makedirs(out, exist_ok=True)
    notices(src, out)
    print("rfc8032", rfc(src, exe, out))
    print("zip215 cases, strict-accepted", zip215(src, exe, out))
    n, skipped, acc = wycheproof(src, exe, out)
    print("wycheproof cases", n, "skipped (length)", skipped)
    print("acceptable (tcId, go strict, consensus)", acc)
    print("edge cases, strict-accepted, consensus-accepted", edge(exe, out))


if __name__ == "__main__":
    main()
