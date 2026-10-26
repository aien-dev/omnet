#!/usr/bin/env python3
"""Test-only binary protocol referee. Abnormal or incomplete runs never kill a mutant."""
import json
import pathlib
import struct
import subprocess
import sys

unit = pathlib.Path(__file__).resolve().parent.parent
repo = unit.parent.parent
rows = [json.loads(x) for x in (unit / 'test/vectors.jsonl').read_text().splitlines()]
wire = bytearray()
expected = bytearray()
for row in rows:
    data = bytes.fromhex(row['Input'])
    keys = b''.join(bytes.fromhex(k) for k in row['Keys'])
    wire += struct.pack('<IH', len(data), len(keys)//32) + bytes.fromhex(row['Node']) + keys + data
    if not row['Decode']:
        expected += b'\0'
    else:
        canon = bytes.fromhex(row['Canon'])
        expected += b'\1' + struct.pack('<I', len(canon)) + canon + bytes.fromhex(row['Hash']) + bytes([row['Auth']])

def complete(out):
    pos = 0
    for row in rows:
        if pos >= len(out):
            return False
        status = out[pos]
        pos += 1
        if status == 1:
            if pos+4 > len(out):
                return False
            n, = struct.unpack_from('<I', out, pos)
            if n > 65536:
                return False
            pos += 4+n+33
        elif status != 0:
            return False
        if pos > len(out):
            return False
    return pos == len(out)

def run(binary):
    p = subprocess.run([str(binary)], input=wire, capture_output=True, timeout=300)
    if p.returncode != 0 or not complete(p.stdout):
        raise RuntimeError(f'ABNORMAL/incomplete {binary.name}: rc={p.returncode}, bytes={len(p.stdout)}, stderr={p.stderr!r}')
    return p.stdout

def explain(out):
    pos = 0
    for row in rows:
        start = pos
        status = out[pos]; pos += 1
        target = b'\0'
        if row['Decode']:
            c = bytes.fromhex(row['Canon'])
            target = b'\1'+struct.pack('<I',len(c))+c+bytes.fromhex(row['Hash'])+bytes([row['Auth']])
        if status:
            n, = struct.unpack_from('<I',out,pos); pos += 4+n+33
        if out[start:pos] != target:
            raise AssertionError(f"{row['Name']}: got {out[start:pos].hex()} expected {target.hex()}")

build = pathlib.Path(sys.argv[2])
omc = sys.argv[1]
parts = [repo/'om'/u/(u+'.om') for u in ('blake2s','sha512','ed25519','cbor')]
prefix = '\n'.join(p.read_text() for p in parts)+'\n'
source = (unit/'tkasig.om').read_text()
driver = (unit/'test/driver.om').read_text()
def compile_one(name, body):
    p = subprocess.run([omc], input=(prefix+body+'\n'+driver).encode(), capture_output=True)
    if p.returncode:
        raise RuntimeError(f'compile {name}: {p.stderr.decode()}')
    binary = build/name
    binary.write_bytes(p.stdout); binary.chmod(0o700)
    return binary

binary = compile_one('driver',source)
out = run(binary)
explain(out)
assert out == expected
assert not complete(out[:-1]), 'incomplete final result accepted'
print(f'PASS tkasig differential {len(rows)} cases')
mutants = {
 'node-binding': ('if ne nksbyte d t get m 1 add j 2 get node j','if eq ulong 0 1'),
 'rotation-consensus': ('nkscheck d t m r pk 0 0','nkscheck d t m r pk 1 0'),
 'direct-strict': ('ret nkscheck d t m r pk 1','ret nkscheck d t m r pk 0'),
 'hash-includes-signature': ('nksser d t m o r 1','nksser d t m o r 0'),
 'unknown-kind': ('if gt cbrval t v 255','if gt cbrval t v 254'),
 'duplicate-alias': ('if ne and seen bit 0','if eq ulong 0 1'),
 'credential-details': ('if gt r 0','if eq ulong 0 1'),
 'simple-kind-rejected': ('if eq nksuint t v 0','if ne cbrmaj t v 0'),
 'simple-bytes-rejected': ('if eq nksuint t j 0','if ne cbrmaj t j 0'),
}
for name,(before,after) in mutants.items():
    assert source.count(before)==1,(name,source.count(before))
    binary=compile_one(name,source.replace(before,after))
    out=run(binary)
    assert out != expected, f'undetected mutant {name}'
    print(f'PASS mutant {name}: completed result mismatch')
# Prove abnormal execution is a harness error, not a detected source mutant.
binary=compile_one('trap-probe',source.replace('ret edverify pk msg 32 sg mode','if eq mode 1\ntrap 3\nend\nret edverify pk msg 32 sg mode'))
try:
    run(binary)
except RuntimeError as e:
    print('PASS harness rejects trapping mutant')
else:
    raise AssertionError('trap probe was not rejected')
