# SPDX-License-Identifier: Apache-2.0
"""Test-vector generator for om/sha512 (test oracle only: python3 hashlib.sha512).

Writes driver records (see driver.om) to stdout:
  gen_vectors.py static        boundary and s512pre vectors committed as vectors/oracle.txt
  gen_vectors.py diff SEED     every length 0..1100, then random lengths up to 65536 (H records)
  gen_vectors.py pre SEED      s512pre records: every length 0..300, then random lengths up to 65536
Output depends only on the arguments (random.Random(SEED)), so a run is reproducible.
"""
import hashlib
import random
import sys

CAP = 65536


def rec_h(m):
    return "H %d %s %s" % (len(m), m.hex() or "-", hashlib.sha512(m).hexdigest())


def rec_p(p, m):
    assert len(p) == 64
    return "P %d %s %s %s" % (len(m), p.hex(), m.hex() or "-", hashlib.sha512(p + m).hexdigest())


def rbytes(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def static():
    rng = random.Random(180)
    out = ["# oracle-generated (python3 hashlib.sha512), not from a NIST document"]
    out.append("# 448-bit message of FIPS 180-4 example set (SHA-256 sample text) hashed with SHA-512")
    out.append(rec_h(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
    out.append("# padding edges: 111/112 (one vs two final blocks), 127/128/129 (block edge), others")
    for n in (0, 1, 55, 56, 63, 64, 110, 111, 112, 113, 119, 120, 126, 127, 128, 129,
              239, 240, 241, 255, 256, 257, 1023, 1024, 1025):
        out.append(rec_h(rbytes(rng, n)))
    out.append("# all-0x00 and all-0xff messages at the edges")
    for n in (111, 112, 127, 128):
        out.append(rec_h(bytes(n)))
        out.append(rec_h(b"\xff" * n))
    out.append("# largest accepted message (n = 65536, CAP)")
    out.append(rec_h(rbytes(rng, CAP)))
    out.append("# s512pre: SHA-512(P || M), P 64 bytes; stream lengths 64 + n cross 111/112/127/128 edges")
    for n in (0, 1, 47, 48, 63, 64, 65, 111, 112, 127, 128, 175, 176, 191, 192, 1000):
        out.append(rec_p(rbytes(rng, 64), rbytes(rng, n)))
    out.append(rec_p(rbytes(rng, 64), rbytes(rng, CAP)))
    return out


def diff(seed):
    rng = random.Random(seed)
    out = [rec_h(rbytes(rng, n)) for n in range(0, 1101)]
    lens = [CAP, CAP - 1, CAP - 17, CAP - 128, CAP - 129, CAP - 16, 32768, 32767]
    lens += [rng.randint(1101, CAP) for _ in range(16)]
    out += [rec_h(rbytes(rng, n)) for n in lens]
    return out


def pre(seed):
    rng = random.Random(seed)
    out = [rec_p(rbytes(rng, 64), rbytes(rng, n)) for n in range(0, 301)]
    lens = [CAP, CAP - 1, CAP - 64, CAP - 65] + [rng.randint(301, CAP) for _ in range(8)]
    out += [rec_p(rbytes(rng, 64), rbytes(rng, n)) for n in lens]
    return out


def main():
    mode = sys.argv[1]
    if mode == "static":
        lines = static()
    elif mode == "diff":
        lines = diff(int(sys.argv[2]))
    elif mode == "pre":
        lines = pre(int(sys.argv[2]))
    else:
        sys.exit("usage: gen_vectors.py static | diff SEED | pre SEED")
    sys.stdout.write("\n".join(lines) + "\n")


main()
