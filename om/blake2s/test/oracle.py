# SPDX-License-Identifier: Apache-2.0
"""Test oracle for om/blake2s: python3 hashlib.blake2s generates vectors only; nothing here ships.

oracle.py boundary          print vectors/boundary.txt (lines: OUTN KN N DIGEST; key byte i = i,
                            message byte i = i mod 251)
oracle.py diff SEED DIR     write DIR/diff.in (driver case lines) and DIR/diff.out (expected digests):
                            every length 0..1100 unkeyed (outn 32) and keyed (kn 1 + L%32,
                            outn 32 - L%32), then 64 seeded-random cases with lengths up to 65536
                            (lengths 65535 and 65536 included), random key length 0..32 and outn 1..32
"""
import hashlib
import os
import random
import sys

CAP = 65536


def pattern(n):
    return bytes(i % 251 for i in range(n))


def line(outn, key, msg):
    return "%d %s %s\n" % (outn, key.hex() or "-", msg.hex() or "-")


def digest(outn, key, msg):
    return hashlib.blake2s(msg, key=key, digest_size=outn).hexdigest()


def boundary():
    edges = [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 191, 192, 193,
             1023, 1024, 1025, 65471, 65472, 65473, 65535, CAP]
    rows = []
    for kn in (0, 32):
        for n in edges:
            rows.append((32, kn, n))
    for kn in (1, 16, 31):
        for n in (0, 64):
            rows.append((32, kn, n))
    for outn in (1, 2, 16, 20, 28, 31):
        for kn in (0, 32):
            rows.append((outn, kn, 64))
    for outn, kn, n in rows:
        print(outn, kn, n, digest(outn, bytes(range(kn)), pattern(n)))


def diff(seed, outdir):
    rng = random.Random(seed)
    cases = []
    for n in range(1101):
        msg = rng.randbytes(n)
        cases.append((32, b"", msg))
        r = n % 32
        cases.append((32 - r, rng.randbytes(1 + r), msg))
    lengths = [CAP - 1, CAP] + [rng.randint(0, CAP) for _ in range(62)]
    for n in lengths:
        kn = rng.choice([0, rng.randint(1, 32)])
        cases.append((rng.randint(1, 32), rng.randbytes(kn), rng.randbytes(n)))
    with open(os.path.join(outdir, "diff.in"), "w") as fi, \
            open(os.path.join(outdir, "diff.out"), "w") as fo:
        for outn, key, msg in cases:
            fi.write(line(outn, key, msg))
            fo.write(digest(outn, key, msg) + "\n")
    print(len(cases))


if __name__ == "__main__":
    if sys.argv[1:] == ["boundary"]:
        boundary()
    elif len(sys.argv) == 4 and sys.argv[1] == "diff":
        diff(int(sys.argv[2]), sys.argv[3])
    else:
        sys.exit(__doc__)
