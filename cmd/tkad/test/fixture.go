// SPDX-License-Identifier: Apache-2.0
// Test-only deterministic fixtures using the real pinned tailscale.com/tka API.
package main

import (
 "bytes"
 "crypto/ed25519"
 "encoding/json"
 "fmt"
 "os"
 "github.com/fxamacker/cbor/v2"
 "tailscale.com/tailcfg"
 "tailscale.com/tka"
 "tailscale.com/types/key"
 "tailscale.com/types/tkatype"
)

func must(e error) { if e != nil { panic(e) } }
func sign(a tka.AUM, p ed25519.PrivateKey) tka.AUM {
 h := a.SigHash()
 a.Signatures = []tkatype.Signature{{KeyID:tkatype.KeyID(p.Public().(ed25519.PublicKey)), Signature:ed25519.Sign(p,h[:])}}
 return a
}
func child(a, prev tka.AUM, p ed25519.PrivateKey) tka.AUM {
 h:=prev.Hash(); a.PrevAUMHash=h[:]; return sign(a,p)
}
func hash(a tka.AUM) string { b,e:=a.Hash().MarshalText(); must(e); return string(b) }
func jsonOracle() {
 var send tailcfg.TKASyncSendRequest
 must(json.Unmarshal([]byte(`{"MiſſingAUMs":["AQ=="],"NodeKey":"nodekey:0909090909090909090909090909090909090909090909090909090909090909"}`), &send))
 if len(send.MissingAUMs)!=1 || send.MissingAUMs[0][0]!=1 || send.NodeKey.IsZero() { panic("Go Unicode field fold changed") }
 for _, name:=range []string{"+1","01","-0"} {
  var finish tailcfg.TKAInitFinishRequest
  must(json.Unmarshal([]byte(`{"Signatures":{"`+name+`":"AQ=="}}`), &finish))
  if len(finish.Signatures)!=1 { panic("Go signed integer map key changed") }
 }
 var finish tailcfg.TKAInitFinishRequest
 if json.Unmarshal([]byte(`{"Signatures":{"9223372036854775808":"AQ=="}}`), &finish)==nil { panic("Go accepted int64 map key overflow") }
}
func main() {
 jsonOracle()
 p:=ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1},32))
 q:=ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2},32))
 secret:=bytes.Repeat([]byte{42},32)
 state:=tka.State{StateID1:123,StateID2:456,DisablementValues:[][]byte{tka.DisablementKDF(secret)},Keys:[]tka.Key{
  {Kind:tka.Key25519,Votes:1,Public:p.Public().(ed25519.PublicKey)},
  {Kind:tka.Key25519,Votes:1,Public:q.Public().(ed25519.PublicKey),Meta:map[string]string{"role":"old"}},
 }}
 genesis:=sign(tka.AUM{MessageKind:tka.AUMCheckpoint,State:&state},p)
 update:=child(tka.AUM{MessageKind:tka.AUMNoOp},genesis,p)
 empty:=child(tka.AUM{MessageKind:tka.AUMUpdateKey,KeyID:tkatype.KeyID(q.Public().(ed25519.PublicKey)),Meta:map[string]string{}},update,p)
 removal:=child(tka.AUM{MessageKind:tka.AUMRemoveKey,KeyID:tkatype.KeyID(q.Public().(ed25519.PublicKey))},empty,p)
 // Serialize omits an empty Meta. Preserve its non-nil typed value on input,
 // while hashing/signing retains upstream canonical omission semantics.
 enc,e:=cbor.CTAP2EncOptions().EncMode(); must(e)
 var wire map[uint64]any
 must(cbor.Unmarshal(empty.Serialize(),&wire)); wire[7]=map[string]string{}
 emptyWire,e:=enc.Marshal(wire); must(e)
 ch:=tka.ChonkMem(); authority,e:=tka.Bootstrap(ch,genesis); must(e)
 nodes:=[]string{}; rots:=[][]byte{}; sigs:=[][]byte{}; goodSigs:=[][]byte{}
 for i:=byte(9);i<12;i++ {
  var np key.NodePublic
  must(np.UnmarshalBinary(append([]byte{'n','p'},bytes.Repeat([]byte{i},32)...)))
  binary,e:=np.MarshalBinary(); must(e)
  rot:=ed25519.NewKeyFromSeed(bytes.Repeat([]byte{i+32},32)).Public().(ed25519.PublicKey)
  s:=tka.NodeKeySignature{SigKind:tka.SigDirect,Pubkey:binary,KeyID:q.Public().(ed25519.PublicKey),WrappingPubkey:rot}
  h:=s.SigHash();s.Signature=ed25519.Sign(q,h[:]);must(authority.NodeKeyAuthorized(np,s.Serialize()))
  nodes=append(nodes,np.String());rots=append(rots,rot);sigs=append(sigs,s.Serialize())
  s.KeyID=p.Public().(ed25519.PublicKey);h=s.SigHash();s.Signature=ed25519.Sign(p,h[:]);goodSigs=append(goodSigs,s.Serialize())
 }
 var decoded tka.AUM;must(decoded.Unserialize(emptyWire));must(decoded.StaticValidate())
 must(authority.Inform(ch,[]tka.AUM{update,decoded,removal}))
 var np key.NodePublic;must(np.UnmarshalText([]byte(nodes[0])))
 if authority.NodeKeyAuthorized(np,sigs[0])==nil { panic("removed signer remains trusted") }
 must(authority.NodeKeyAuthorized(np,goodSigs[0]))
 if !authority.ValidDisablement(secret) { panic("disablement mismatch") }
 result:=map[string]any{"genesis":genesis.Serialize(),"head":hash(genesis),"update":update.Serialize(),"updatedHead":hash(update),"emptyMeta":emptyWire,"emptyHead":hash(empty),"removal":removal.Serialize(),"removedHead":hash(removal),"nodes":nodes,"rotations":rots,"signatures":sigs,"goodSignatures":goodSigs,"keyID":q.Public().(ed25519.PublicKey),"secret":secret,"source":"tailscale.com v1.102.0 real tka authority"}
 b,e:=json.MarshalIndent(result,"","  ");must(e);fmt.Fprintln(os.Stdout,string(b))
}
