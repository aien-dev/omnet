# SPDX-License-Identifier: Apache-2.0
"""Vector generator for om/argon2 (test only; nothing here ships).

vectors.py ORACLE > ../vectors/go-diff.txt        the committed corpus
vectors.py ORACLE random SEED N > FILE            N random small parameter sets (run.sh, optional)

Builds the case list below (seeded, deterministic), runs the Go referee ORACLE (gen/oracle, built
from golang.org/x/crypto v0.54.0, the version tailscale.com v1.102.0 pins) on it, and prints one
line per case: the driver input line followed by the expected tag in lowercase hex.
  case T M P TL PW SALT KEY AD TAG
  tka SEC TAG
"""
import random
import subprocess
import sys


def hx(b):
    return b.hex() or "-"


def cases():
    rng = random.Random(9106)
    rb = rng.randbytes
    out = []
    # (t, m KiB, p, tag length, |P|, |S|, |K|, |X|)
    sets = [
        (1, 8, 1, 32, 32, 16, 0, 0),        # smallest memory: m' = 8, one lane
        (2, 64, 1, 32, 0, 16, 0, 0),        # empty password
        (3, 32, 4, 32, 32, 16, 8, 12),      # RFC 9106 5.2 shape, random bytes
        (1, 37, 2, 32, 16, 16, 0, 0),       # m not a multiple of 4p: m' = 32
        (2, 63, 3, 16, 10, 8, 0, 0),        # p = 3, m' = 60
        (3, 100, 5, 24, 20, 12, 4, 0),      # p = 5, m' = 100, with K
        (1, 64, 8, 32, 8, 8, 0, 5),         # p = 8 (minimum m = 8p), with X
        (4, 256, 16, 32, 32, 16, 0, 0),     # p = 16
        (2, 1536, 3, 32, 32, 16, 0, 0),     # p = 3, segment length exactly 128
        (1, 1024, 1, 32, 32, 16, 0, 0),     # segment length 256: 2 address blocks
        (2, 2048, 2, 32, 32, 16, 32, 32),   # segment length 256, K and X
        (1, 4096, 1, 64, 64, 32, 0, 0),     # segment length 1024: 8 address blocks
        (1, 512, 1, 32, 32, 16, 0, 0),      # segment length 128 from index 2: one address block
        (1, 16, 2, 4, 3, 8, 0, 0),          # tag length 4 (minimum)
        (1, 16, 2, 5, 3, 8, 0, 0),          # tag length 5
        (1, 16, 1, 63, 12, 16, 0, 0),       # tag 63
        (1, 16, 1, 64, 12, 16, 0, 0),       # tag 64: last single BLAKE2b call
        (1, 16, 1, 65, 12, 16, 0, 0),       # tag 65: first H' chain (r = 1)
        (1, 16, 1, 96, 12, 16, 0, 0),       # tag 96
        (1, 16, 1, 100, 12, 16, 0, 0),      # tag 100
        (1, 16, 1, 128, 12, 16, 0, 0),      # tag 128
        (1, 16, 1, 129, 12, 16, 0, 0),      # tag 129
        (1, 16, 1, 512, 12, 16, 0, 0),      # tag 512
        (1, 16, 1, 1024, 12, 16, 0, 0),     # tag 1024 (maximum)
        (5, 48, 3, 32, 200, 300, 32, 400),  # long inputs
        (1, 32, 1, 32, 4000, 16, 64, 4000), # H0 input of several BLAKE2b blocks
        (1, 8, 1, 32, 65480, 16, 0, 0),     # H0 input at the 65496-byte capacity
        (1, 16384, 1, 32, 32, 16, 0, 0),    # 16 MiB, one lane
        (1, 16384, 4, 32, 32, 39, 0, 0),    # 16 MiB, four lanes
        (2, 16383, 4, 32, 16, 16, 0, 0),    # m' = 16368
        (4, 16384, 4, 32, 32, 39, 0, 0),    # TKA cost parameters, random salt
    ]
    for t, m, p, tl, pn, sn, kn, xn in sets:
        out.append("case %d %d %d %d %s %s %s %s" % (
            t, m, p, tl, hx(rb(pn)), hx(rb(sn)), hx(rb(kn)), hx(rb(xn))))
    for n in (0, 1, 16, 32, 32, 32, 32, 33, 64, 1024):
        out.append("tka %s" % hx(rb(n)))
    return out


def randcases(seed, count):
    """count random small parameter sets: t 1..4, p 1..8, m 8p..8p+120, T 4..200, random input
    lengths (|P| 0..300, |S| 0..64, |K| 0..64, |X| 0..64, each 0 with probability 1/4)."""
    rng = random.Random(seed)

    def ln(hi):
        return 0 if rng.random() < 0.25 else rng.randint(1, hi)

    out = []
    for _ in range(count):
        p = rng.randint(1, 8)
        out.append("case %d %d %d %d %s %s %s %s" % (
            rng.randint(1, 4), rng.randint(8 * p, 8 * p + 120), p, rng.randint(4, 200),
            hx(rng.randbytes(ln(300))), hx(rng.randbytes(ln(64))),
            hx(rng.randbytes(ln(64))), hx(rng.randbytes(ln(64)))))
    return out


def main():
    oracle = sys.argv[1]
    if len(sys.argv) == 5 and sys.argv[2] == "random":
        lines = randcases(int(sys.argv[3]), int(sys.argv[4]))
    elif len(sys.argv) == 2:
        lines = cases()
    else:
        sys.exit(__doc__)
    feed = "".join(l.split(" ", 1)[1] + "\n" if l.startswith("case ") else l + "\n" for l in lines)
    res = subprocess.run([oracle], input=feed.encode(), capture_output=True, check=True)
    tags = res.stdout.decode().split("\n")[:-1]
    if len(tags) != len(lines):
        sys.exit("oracle returned %d lines for %d cases" % (len(tags), len(lines)))
    for l, t in zip(lines, tags):
        print(l, t)


if __name__ == "__main__":
    main()
