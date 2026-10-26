#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile test-only syscall-boundary fault variants; never production switches."""
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

root, binary = map(pathlib.Path, sys.argv[1:])
source = pathlib.Path(str(binary) + ".om").read_text()
omc = subprocess.check_output(["sh",str(root/"tools/omc.sh")],text=True).strip()
fixture = json.loads((root/"cmd/tkad/test/fixture.json").read_text())
write_needle = "fn stwr fd int b view uchar 65536 off ulong n ulong to long\nret write fd b off n\nend"
sync_needle = "fn stsync fd int to long\nret fsync fd\nend"
assert source.count(write_needle)==1 and source.count(sync_needle)==1


def build(label, needle, replacement):
    p = subprocess.run([omc],input=source.replace(needle,replacement).encode(),capture_output=True)
    assert p.returncode==0,p.stderr.decode()
    path=root/"build"/("tkad-fault-"+label);path.write_bytes(p.stdout);path.chmod(0o700)
    return path


def start(binary, state, init=False):
    p=subprocess.Popen([str(binary),str(state)]+(["--init"] if init else []),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        assert p.poll() is None,(p.returncode,p.communicate())
        try:
            with socket.socket(socket.AF_UNIX) as s:s.connect(str(state/"tkad.sock"))
            return p
        except (FileNotFoundError,ConnectionRefusedError):time.sleep(.01)
    raise AssertionError("startup timeout")


def rpc(state, route, body, node=0):
    data=json.dumps(body).encode()
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(10);s.connect(str(state/"tkad.sock"))
        s.sendall(struct.pack("<4sBBHQI",b"TKA\x01",route,1,0,node,len(data))+data)
        def exact(n):
            b=b""
            while len(b)<n:
                x=s.recv(n-len(b))
                if not x:return None
                b+=x
            return b
        head=exact(12)
        if head is None:return None,None
        magic,status,zero,n=struct.unpack("<4sHHI",head)
        assert magic==b"TKA\x01" and zero==0
        return status,json.loads(exact(n))


register=dict(NodeID=1,NodeKey=fixture["nodes"][0],RotationPubkey=fixture["rotations"][0])
for size,label in [(56,"terminator"),(16,"begin-header")]:
    replacement=f"""global ds_fault ulong 1
fn stwr fd int b view uchar 65536 off ulong n ulong to long
if eq n {size}
put ds_fault 0 add get ds_fault 0 1
if eq get ds_fault 0 2
ret -28
end
end
ret write fd b off n
end"""
    mutant=build(label,write_needle,replacement)
    with tempfile.TemporaryDirectory(prefix="tkad-precommit-") as name:
        state=pathlib.Path(name);p=start(mutant,state,True)
        try:
            before=rpc(state,11,{})
            assert rpc(state,9,register)[0]==503
            assert rpc(state,11,{})==before,"failed candidate became visible"
            assert rpc(state,9,register)[0]==200,"transient failure poisoned future mutation"
            status,after=rpc(state,11,{})
            assert status==200 and after["Revision"]==1 and len(after["Nodes"])==1
            assert p.poll() is None
        finally:p.kill();p.communicate(timeout=10)
    print(f"PASS tkad one-shot {label} ENOSPC: 503, unchanged live state, next mutation succeeds")

replacement="""global ds_fault ulong 1
fn stsync fd int to long
put ds_fault 0 add get ds_fault 0 1
if eq get ds_fault 0 4
ret -5
end
ret fsync fd
end"""
mutant=build("uncertain",sync_needle,replacement)
with tempfile.TemporaryDirectory(prefix="tkad-uncertain-") as name:
    state=pathlib.Path(name);p=start(mutant,state,True)
    assert rpc(state,9,register)==(None,None),"uncertain commit sent a normal response"
    p.communicate(timeout=10);assert p.returncode==74,p.returncode
    p=start(binary,state)
    try:
        status,after=rpc(state,11,{})
        assert status==200 and after["Revision"]==1 and len(after["Nodes"])==1,"renamed candidate lost"
    finally:p.kill();p.communicate(timeout=10)
print("PASS tkad post-rename directory-fsync EIO: fatal74, no reply, renamed candidate recovered")


def frames(snapshot):
    result=[];p=16
    while True:
        n=struct.unpack_from("<Q",snapshot,p)[0]
        if n==0:return result
        result.append(bytearray(snapshot[p+40:p+40+n]))
        p+=40+n


def reseal(magic, payloads):
    # Independent Python implementation of the documented store framing.
    out=bytearray(magic);chain=bytes(32);total=0
    for count,payload in enumerate(payloads,1):
        digest=hashlib.blake2s(payload).digest();total+=len(payload)
        out+=struct.pack("<Q",len(payload))+digest+payload
        chain=hashlib.blake2s(chain+digest+struct.pack("<QQQ",len(payload),total,count)).digest()
    out+=bytes(8)+chain+struct.pack("<QQ",total,len(payloads))
    return out


with tempfile.TemporaryDirectory(prefix="tkad-semantic-recovery-") as name:
    state=pathlib.Path(name);p=start(binary,state,True)
    common=dict(Version=131,NodeKey=fixture["nodes"][0])
    try:
        assert rpc(state,9,register)[0]==200
        assert rpc(state,1,dict(common,GenesisAUM=fixture["genesis"]),1)[0]==200
        pending=(state/"snapshot").read_bytes()
        assert rpc(state,2,dict(common,Signatures={"1":fixture["signatures"][0]},SupportDisablement=fixture["secret"]),1)[0]==200
    finally:p.kill();p.communicate(timeout=10)
    active=(state/"snapshot").read_bytes()
    # Prove the independent reframer writes a valid baseline before using it
    # to distinguish semantic validation from the checksum layer.
    (state/"snapshot").write_bytes(reseal(active[:16],frames(active)))
    p=start(binary,state);p.kill();p.communicate(timeout=10)
    for label,index,offset in [("signature",2,-1),("support-secret",3,0),("genesis",4,-1),("reserved-metadata",0,40)]:
        payloads=frames(active);payloads[index][offset]^=1
        (state/"snapshot").write_bytes(reseal(active[:16],payloads))
        refused=subprocess.run([str(binary),name],capture_output=True,timeout=10)
        assert refused.returncode==73,(label,refused.returncode,refused.stderr)
    payloads=frames(pending);struct.pack_into("<Q",payloads[0],16,99)
    (state/"snapshot").write_bytes(reseal(pending[:16],payloads))
    refused=subprocess.run([str(binary),name],capture_output=True,timeout=10)
    assert refused.returncode==73
print("PASS tkad checksum-valid semantic corruption: NKS, genesis, support secret, reserved metadata, pending initiator rejected")
canon_needle = """note Store the canonical form; an empty signature still clears the node.
fn dssetcanon i ulong src view uchar 65536 n ulong auth ulong to ulong
if eq n 0
dssetsig i src 0 auth
ret 0
end
c = new uchar 65536 0
z = dscanon src n c
if gt z 65536
ret 1
end
dssetsig i c z auth
ret 0
end"""
assert source.count(canon_needle)==1
# Test-only: keep submitted bytes so an ignored CBOR field can reach the limit.
raw_store=build("raw-store",canon_needle,"""note Test-only raw storage to exercise the registry capacity guard.
fn dssetcanon i ulong src view uchar 65536 n ulong auth ulong to ulong
dssetsig i src n auth
ret 0
end""")


def padded(signature, size):
    raw=base64.b64decode(signature)
    assert 0xa0<=raw[0]<=0xb7
    pad=b"\x18\x63"
    n=size-len(raw)-len(pad)-1-5
    assert n>0
    return base64.b64encode(bytes([raw[0]+1])+raw[1:]+pad+b"\x5a"+struct.pack(">I",n)+bytes(n)).decode()


with tempfile.TemporaryDirectory(prefix="tkad-registry-capacity-") as name:
    state=pathlib.Path(name);p=start(raw_store,state,True)
    for i in (0,1):
        assert rpc(state,9,dict(NodeID=i+1,NodeKey=fixture["nodes"][i],RotationPubkey=fixture["rotations"][i]))[0]==200
    common=dict(Version=131,NodeKey=fixture["nodes"][0])
    try:
        assert rpc(state,1,dict(common,GenesisAUM=fixture["genesis"]),1)[0]==200
        assert rpc(state,2,dict(common,Signatures={"1":fixture["signatures"][0],"2":fixture["signatures"][1]}),1)[0]==200
        assert rpc(state,9,dict(NodeID=3,NodeKey=fixture["nodes"][2],RotationPubkey=fixture["rotations"][2]))[0]==200
        assert rpc(state,7,dict(Version=131,NodeKey=fixture["nodes"][2],Signature=padded(fixture["signatures"][2],30000)),3)[0]==200
        first=rpc(state,11,{})[1]
        assert len(first["Nodes"])==3 and first["Nodes"][2]["KeySignature"]==padded(fixture["signatures"][2],30000),first
        # A second individually valid signature would push the registry past the
        # map response limit; the candidate must be rejected, never committed.
        assert rpc(state,7,dict(common,Signature=padded(fixture["signatures"][0],30000)),1)[0]==413
        assert rpc(state,11,{})[1]==first,"rejected candidate cannot change the registry"
    finally:p.kill();p.communicate(timeout=10)
    p=start(raw_store,state)
    try:
        assert rpc(state,11,{})[1]==first,"over-capacity rejection is durable, registry still readable"
    finally:p.kill();p.communicate(timeout=10)
print("PASS tkad registry capacity guard: ignored CBOR padding rejected 413, registry unchanged and readable")

