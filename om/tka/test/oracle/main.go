// SPDX-License-Identifier: Apache-2.0
// Test-only oracle. Protocol decisions come from the pinned tailscale.com/tka.
package main

import (
 "bufio"
 "bytes"
 "crypto/ed25519"
 "encoding/json"
 "encoding/binary"
 "encoding/hex"
 "fmt"
 "os"
 "path/filepath"
 "strings"

 "github.com/fxamacker/cbor/v2"
 "tailscale.com/tka"
 "tailscale.com/types/tkatype"
 "tailscale.com/types/key"
)

var input, expected *os.File
var auth [2]*tka.Authority
var store [2]*tka.Mem
var enc cbor.EncMode
var dec cbor.DecMode
func must(err error) { if err != nil { panic(err) } }
func emit(cmd, slot byte, data []byte) { input.Write([]byte{cmd,slot}); must(binary.Write(input,binary.LittleEndian,uint32(len(data)))); input.Write(data) }
func line(b []byte) { fmt.Fprintf(expected,"%x\n",b) }
func status(err error) { if err != nil { line([]byte{1}) } else { line([]byte{0}) } }
func marshal(v any) []byte { b,e:=enc.Marshal(v); must(e); return b }
func model(b []byte, schema byte) {
 emit(10+schema,0,b)
 var a tka.AUM
 var value any
 var err error
 switch schema {case 1: err=a.Unserialize(b); value=a; case 2: var k tka.Key; err=dec.Unmarshal(b,&k); value=k; case 3: var s tka.State; err=dec.Unmarshal(b,&s); value=s; case 4: var s tkatype.Signature; err=dec.Unmarshal(b,&s); value=s}
 status(err); if err!=nil{return}; line(marshal(value))
 if schema==1 { h:=a.Hash(); line(h[:]); sh:=a.SigHash(); line(sh[:]); status(a.StaticValidate()) }
}
func reset(slot byte) { emit(4,slot,nil); status(nil); store[slot]=tka.ChonkMem(); auth[slot]=nil }
func head(slot byte) { var h tka.AUMHash; if auth[slot]!=nil {h=auth[slot].Head()}; line(h[:]) }
func boot(slot byte,a tka.AUM) { emit(2,slot,a.Serialize()); v,e:=tka.Bootstrap(store[slot],a); if e==nil{auth[slot]=v}; status(e); head(slot) }
func inform(slot byte, updates ...tka.AUM) {
 var b bytes.Buffer; b.WriteByte(byte(len(updates)))
 for _,a:=range updates { raw:=a.Serialize(); binary.Write(&b,binary.LittleEndian,uint32(len(raw))); b.Write(raw) }
 emit(3,slot,b.Bytes()); err:=auth[slot].Inform(store[slot],updates); status(err); head(slot)
}
func informRaw(slot byte, raw []byte) {
 var a tka.AUM;must(a.Unserialize(raw))
 var b bytes.Buffer;b.WriteByte(1);binary.Write(&b,binary.LittleEndian,uint32(len(raw)));b.Write(raw)
 emit(3,slot,b.Bytes());status(auth[slot].Inform(store[slot],[]tka.AUM{a}));head(slot)
}
func keys(slot byte) { emit(8,slot,nil); status(nil); var b []byte; for _,k:=range auth[slot].Keys(){ if k.Kind==tka.Key25519&&len(k.Public)==32{b=append(b,k.Public...)} }; line(b) }
func offer(slot byte) tka.SyncOffer { o,e:=auth[slot].SyncOffer(store[slot]); must(e); emit(5,slot,nil); status(nil); line(offerBytes(o)); return o }
func offerBytes(o tka.SyncOffer) []byte { b:=append([]byte{},o.Head[:]...);for _,h:=range o.Ancestors{b=append(b,h[:]...)};return b }
func missing(slot byte,o tka.SyncOffer) []tka.AUM { emit(6,slot,offerBytes(o)); a,e:=auth[slot].MissingAUMs(store[slot],o);status(e);if e==nil{var b []byte;for _,x:=range a{h:=x.Hash();b=append(b,h[:]...)};line(b)};return a }
func stateAt(slot byte,h tka.AUMHash,s tka.State) { emit(7,slot,h[:]);status(nil);s.LastAUMHash=&h;line(marshal(s)) }
func sign(a tka.AUM, privs ...ed25519.PrivateKey) tka.AUM { a.Signatures=nil; h:=a.SigHash();for _,p:=range privs{a.Signatures=append(a.Signatures,tkatype.Signature{KeyID:tkatype.KeyID(p.Public().(ed25519.PublicKey)),Signature:ed25519.Sign(p,h[:])})};return a }
func child(a tka.AUM, p tka.AUM, privs ...ed25519.PrivateKey) tka.AUM {h:=p.Hash();a.PrevAUMHash=h[:];return sign(a,privs...) }
func corpus(root string) {
 for _,name:=range []string{"hostile.txt","fuzz.txt","tka-structs.txt"} {
 f,e:=os.Open(filepath.Join(root,name));must(e);scan:=bufio.NewScanner(f);scan.Buffer(make([]byte,65536),2<<20)
 for scan.Scan(){s:=strings.Fields(scan.Text());if len(s)==0||strings.HasPrefix(s[0],"#"){continue};var raw string;schema:=byte(1)
 if name=="tka-structs.txt" {if s[0]=="aum"{raw=s[1]}else if s[0]=="state"{raw=s[1];schema=3}else{continue}} else {if s[1]!="aum"{continue};raw=s[5]}
 var b []byte;if raw!="-"{b,e=hex.DecodeString(raw);must(e)};model(b,schema)
 };must(scan.Err());f.Close()
 }
}
func scenarios() {
 p:=ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1},32));q:=ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2},32));r:=ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3},32))
 k:=tka.Key{Kind:tka.Key25519,Votes:1,Public:p.Public().(ed25519.PublicKey)}; k2:=tka.Key{Kind:tka.Key25519,Votes:2,Public:q.Public().(ed25519.PublicKey)}; k3:=tka.Key{Kind:tka.Key25519,Votes:3,Public:r.Public().(ed25519.PublicKey)}
 state:=tka.State{DisablementValues:[][]byte{bytes.Repeat([]byte{7},32)},Keys:[]tka.Key{k,k2},StateID1:11,StateID2:22}
 g:=sign(tka.AUM{MessageKind:tka.AUMCheckpoint,State:&state},p)
 reset(0);reset(1);boot(0,g);boot(1,g);boot(0,g);keys(0);stateAt(0,g.Hash(),state)
 add:=child(tka.AUM{MessageKind:tka.AUMAddKey,Key:&k3},g,p);inform(0,add);keys(0)
 st1:=state.Clone();st1.Keys=append(st1.Keys,k3);stateAt(0,add.Hash(),st1)
 votes:=uint(4);up:=child(tka.AUM{MessageKind:tka.AUMUpdateKey,KeyID:k.Public,Votes:&votes,Meta:map[string]string{"name":"alpha"}},add,p)
 inform(0,up);st2:=st1.Clone();st2.Keys[0].Votes=4;st2.Keys[0].Meta=map[string]string{"name":"alpha"};stateAt(0,up.Hash(),st2)
 cp:=child(tka.AUM{MessageKind:tka.AUMCheckpoint,State:&st2},up,p);inform(0,cp);stateAt(0,cp.Hash(),st2)
 badstate:=st2.Clone();badstate.StateID2++;badcp:=child(tka.AUM{MessageKind:tka.AUMCheckpoint,State:&badstate},cp,p);inform(0,badcp)
 rm:=child(tka.AUM{MessageKind:tka.AUMRemoveKey,KeyID:k2.Public},cp,p);inform(0,rm);keys(0)
 off:=offer(1);miss:=missing(0,off);inform(1,miss...);offer(0);offer(1);keys(1)
 unknown:=child(tka.AUM{MessageKind:255,KeyID:[]byte{42}},rm,p);inform(0,unknown)
 invalid:=child(tka.AUM{MessageKind:tka.AUMNoOp},unknown,q);inform(0,invalid)
 badparent:=sign(tka.AUM{MessageKind:tka.AUMNoOp,PrevAUMHash:bytes.Repeat([]byte{99},32)},p);inform(0,badparent)
 good:=child(tka.AUM{MessageKind:tka.AUMNoOp},unknown,p);inform(0,good,badparent);inform(0,good);inform(0,good)
 unsigned:=child(tka.AUM{MessageKind:tka.AUMNoOp},good);inform(0,unsigned)
 badsig:=child(tka.AUM{MessageKind:tka.AUMNoOp},good,p);badsig.Signatures[0].Signature[0]^=1;inform(0,badsig)
 adddup:=child(tka.AUM{MessageKind:tka.AUMAddKey,Key:&k3},good,p);inform(0,adddup)
 zero:=uint(0);badup:=child(tka.AUM{MessageKind:tka.AUMUpdateKey,KeyID:k.Public,Votes:&zero},good,p);inform(0,badup)
 missing(0,tka.SyncOffer{Head:tka.AUMHash{99},Ancestors:[]tka.AUMHash{{98}}})
 // Fork choice: duplicate signatures contribute votes once; remove wins a weight tie.
 reset(0);reset(1);boot(0,g);boot(1,g)
 dup:=child(tka.AUM{MessageKind:tka.AUMNoOp,KeyID:[]byte{1}},g,p,p,p)
 heavy:=child(tka.AUM{MessageKind:tka.AUMNoOp,KeyID:[]byte{2}},g,q)
 inform(0,dup,heavy);inform(1,heavy,dup);offer(0);offer(1)
 remove:=child(tka.AUM{MessageKind:tka.AUMRemoveKey,KeyID:k.Public},g,q);inform(0,remove);keys(0);inform(1,remove);keys(1)
 // Hash tie breaker among equal-weight siblings; different arrival orders converge.
 a:=child(tka.AUM{MessageKind:tka.AUMNoOp,KeyID:[]byte{3}},remove,q)
 b:=child(tka.AUM{MessageKind:tka.AUMNoOp,KeyID:[]byte{4}},remove,q)
 inform(0,a);inform(1,b);o0:=offer(0);o1:=offer(1);m0:=missing(0,o1);m1:=missing(1,o0);inform(0,m1...);inform(1,m0...);offer(0);offer(1)
 last:=a;if b.Hash().String()<a.Hash().String(){last=b};if auth[0].Head()!=last.Hash(){last=b}
 lastRemove:=child(tka.AUM{MessageKind:tka.AUMRemoveKey,KeyID:k2.Public},last,q);inform(0,lastRemove)
 // Preserve original bootstrap at a later checkpoint, including non-nil parent.
 reset(1);boot(1,cp);keys(1);offer(1)
 // Exact sampled oldest duplicates at depth4,16,64; bounded long-chain synchronization.
 reset(0);reset(1);boot(0,g);boot(1,g);last=g
 for i:=range 70{last=child(tka.AUM{MessageKind:tka.AUMNoOp,KeyID:[]byte{byte(i)}},last,p);inform(0,last);if i==3||i==15||i==63{offer(0)}}
 o1=offer(1);m0=missing(0,o1);inform(1,m0...);offer(0);offer(1)
 // Bounded-profile resource tests are deliberately distinct from upstream acceptance.
 for i:=70;i<126;i++{last=child(tka.AUM{MessageKind:tka.AUMNoOp,KeyID:[]byte{byte(i)}},last,p);inform(0,last)}
 next:=child(tka.AUM{MessageKind:tka.AUMNoOp,KeyID:[]byte{126}},last,p)
 overflow:=child(tka.AUM{MessageKind:tka.AUMNoOp,KeyID:[]byte{127}},next,p)
 rejectBatch(0,next,overflow);offer(0);keys(0);inform(0,next);rejectBatch(0,overflow);offer(0)
 // The 512-key checkpoint fits; AddKey must reject a 513th without mutation.
 big:=state.Clone();big.Keys=[]tka.Key{k}
 for i:=range 511{pub:=bytes.Repeat([]byte{42},32);binary.LittleEndian.PutUint64(pub,uint64(i));big.Keys=append(big.Keys,tka.Key{Kind:tka.Key25519,Votes:1,Public:pub})}
 bg:=sign(tka.AUM{MessageKind:tka.AUMCheckpoint,State:&big},p);reset(0);boot(0,bg)
 rejectBatch(0,child(tka.AUM{MessageKind:tka.AUMAddKey,Key:&k3},bg,p));keys(0);offer(0)
 // Static validation boundaries and typed forms.
 for _,v:=range []uint{0,1,4096,4097}{kk:=k.Clone();kk.Votes=v;model(marshal(kk),2);a:=tka.AUM{MessageKind:tka.AUMAddKey,Key:&kk};model(a.Serialize(),1)}
 for _,s:=range []string{"a201180302f6","a261310361328100","a3010302f6181861ff","a3010302f607a1f6f6","a3010302f607a2606161f66162","a3010302f60460","a3010302f60380","a3010302f606f6","f6","a2010302f7"}{b,e:=hex.DecodeString(s);must(e);model(b,1)}
 for _,raw:=range []string{"a1014101","a1018101","a10158200000000000000000000000000000000000000000000000000000000000000000","a10180","a101f6","a10380","a103f6"}{b,e:=hex.DecodeString(raw);must(e);model(b,3)}
 for _,raw:=range []string{"a101190100","a3010102010340","a30101020103f6","a40101020103400ca1f6f6"}{b,e:=hex.DecodeString(raw);must(e);model(b,2)}
 for _,raw:=range []string{"a201810102820001","a2014002f6","a2016002f6","a201f60280"}{b,e:=hex.DecodeString(raw);must(e);model(b,4)}
 nilkey:=k.Clone();nilkey.Public=nil;emptykey:=k.Clone();emptykey.Public=[]byte{}
 ns:=state.Clone();ns.Keys=[]tka.Key{k,nilkey,emptykey};na:=tka.AUM{MessageKind:tka.AUMCheckpoint,State:&ns};model(na.Serialize(),1)
 ns.Keys=[]tka.Key{k,nilkey};na.State=&ns;model(na.Serialize(),1)
 // Empty-but-present Meta clears metadata even though canonical reserialization omits it.
 reset(0);boot(0,g)
 named:=child(tka.AUM{MessageKind:tka.AUMUpdateKey,KeyID:k.Public,Meta:map[string]string{"name":"temporary"}},g,p);inform(0,named)
 clear:=child(tka.AUM{MessageKind:tka.AUMUpdateKey,KeyID:k.Public,Meta:map[string]string{}},named,p)
 wire:=marshal(map[uint64]any{1:clear.MessageKind,2:clear.PrevAUMHash,4:clear.KeyID,7:map[string]string{},23:clear.Signatures})
 model(wire,1);informRaw(0,wire);stateAt(0,clear.Hash(),state)
 // Replaying its canonical (now statically invalid) encoding must skip revalidation by hash.
 informRaw(0,clear.Serialize());stateAt(0,clear.Hash(),state)
 // fxamacker treats non-Boolean simple values as unsigned integers in typed destinations.
 for v:=range 256 {
  value:=[]byte{0xf8,byte(v)};if v<24{value=[]byte{0xe0+byte(v)}}
  for _,schema:=range []byte{1,2}{model(append([]byte{0xa1,1},value...),schema)}
  model(append([]byte{0xa1,6},value...),1)
  model(append([]byte{0xa1,4},value...),3)
  model(append([]byte{0xa1,2,0x81},value...),1)
  model(append([]byte{0xa1,1,0x81},value...),3)
  model(append([]byte{0xa1,1,0x81},value...),4)
 }
}
func rejectBatch(slot byte,updates ...tka.AUM) {
 var b bytes.Buffer;b.WriteByte(byte(len(updates)))
 for _,a:=range updates{raw:=a.Serialize();binary.Write(&b,binary.LittleEndian,uint32(len(raw)));b.Write(raw)}
 emit(3,slot,b.Bytes());status(fmt.Errorf("explicit bounded-profile resource rejection"));head(slot)
}
func fixture() {
 p:=ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1},32));q:=ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2},32))
 k:=tka.Key{Kind:tka.Key25519,Votes:1,Public:p.Public().(ed25519.PublicKey)}
 k2:=tka.Key{Kind:tka.Key25519,Votes:1,Public:q.Public().(ed25519.PublicKey)}
 s:=tka.State{Keys:[]tka.Key{k,k2},DisablementValues:[][]byte{bytes.Repeat([]byte{7},32)}}
 g:=sign(tka.AUM{MessageKind:tka.AUMCheckpoint,State:&s},p)
 rm:=child(tka.AUM{MessageKind:tka.AUMRemoveKey,KeyID:k2.Public},g,p)
 node:=bytes.Repeat([]byte{9},32)
 var np key.NodePublic;must(np.UnmarshalBinary(append([]byte{'n','p'},node...)))
 pub,e:=np.MarshalBinary();must(e)
 sig:=tka.NodeKeySignature{SigKind:tka.SigDirect,Pubkey:pub,KeyID:k2.Public}
 h:=sig.SigHash();sig.Signature=ed25519.Sign(q,h[:])
 ch:=tka.ChonkMem();a,e:=tka.Bootstrap(ch,g);must(e)
 must(a.NodeKeyAuthorized(np,sig.Serialize()))
 must(a.Inform(ch,[]tka.AUM{rm}))
 if a.NodeKeyAuthorized(np,sig.Serialize())==nil{panic("fixture remains authorized after removal")}
 must(json.NewEncoder(os.Stdout).Encode(map[string]string{"genesis":hex.EncodeToString(g.Serialize()),"removal":hex.EncodeToString(rm.Serialize()),"signature":hex.EncodeToString(sig.Serialize()),"node":hex.EncodeToString(node)}))
}
func main(){if len(os.Args)==2&&os.Args[1]=="--fixture"{fixture();return};if len(os.Args)!=4{panic("oracle INPUT EXPECTED CBOR_VECTOR_DIR")};var e error;input,e=os.Create(os.Args[1]);must(e);defer input.Close();expected,e=os.Create(os.Args[2]);must(e);defer expected.Close();enc,e=cbor.CTAP2EncOptions().EncMode();must(e)
 // Derived options from tka/tka.go; Tailscale BSD-3-Clause, notice in ../../tailscale.LICENSE.
 dec,e=(cbor.DecOptions{DupMapKey:cbor.DupMapKeyEnforcedAPF,IndefLength:cbor.IndefLengthForbidden,TagsMd:cbor.TagsForbidden,MaxNestedLevels:16,MaxArrayElements:4096,MaxMapPairs:1024}).DecMode();must(e)
 scenarios();corpus(os.Args[3])
}
