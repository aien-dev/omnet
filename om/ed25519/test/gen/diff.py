# SPDX-License-Identifier: Apache-2.0
"""Differential corpus for om/ed25519 (test tooling only; needs pynacl and cryptography).

Usage: python3 diff.py OUTDIR COUNT SEED
Writes OUTDIR/diff-NN.txt (driver line format, at most 400 keypairs per file): for each of COUNT
keypairs, a random message of 0..4096 bytes signed by pynacl (even index) or cryptography (odd
index), expected valid in both modes, then the same case with one random bit of pk || sig || msg
flipped, expected invalid in both modes. Each signature is also checked by the signing library.
"""
import os
import random
import sys

import nacl.signing
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def keypair_sign(i, seed, msg):
    if i % 2 == 0:
        sk = nacl.signing.SigningKey(seed)
        sig = sk.sign(msg).signature
        pk = sk.verify_key.encode()
        sk.verify_key.verify(msg, sig)
    else:
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        sig = sk.sign(msg)
        pub = sk.public_key()
        pk = pub.public_bytes(*RAW)
        pub.verify(sig, msg)
    return pk, sig


def main():
    out, count, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    os.makedirs(out, exist_ok=True)
    rnd = random.Random(seed)
    per = 400
    files = 0
    for start in range(0, count, per):
        with open(os.path.join(out, f"diff-{files:02d}.txt"), "w") as f:
            for i in range(start, min(count, start + per)):
                msg = rnd.randbytes(rnd.randrange(0, 4097))
                pk, sig = keypair_sign(i, rnd.randbytes(32), msg)
                f.write(f"1 1 {pk.hex()} {sig.hex()} {msg.hex()}\n")
                blob = bytearray(pk + sig + msg)
                bit = rnd.randrange(0, 8 * len(blob))
                blob[bit // 8] ^= 1 << (bit % 8)
                fp, fs, fm = bytes(blob[:32]), bytes(blob[32:96]), bytes(blob[96:])
                f.write(f"0 0 {fp.hex()} {fs.hex()} {fm.hex()}\n")
        files += 1
    print(f"diff: {count} keypairs, {2 * count} cases, {files} files, seed {seed}")


if __name__ == "__main__":
    main()
