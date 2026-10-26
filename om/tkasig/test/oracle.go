// SPDX-License-Identifier: Apache-2.0
// Test-only oracle calls Tailscale v1.102.0, fetched 2026-10-25.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"math/rand/v2"
	"os"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

type row struct {
	Name   string
	Input  string
	Node   string
	Keys   []string
	Decode bool
	Canon  string
	Hash   string
	Auth   bool
}

var enc = json.NewEncoder(os.Stdout)
var root = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
var wrap = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
var pub = root.Public().(ed25519.PublicKey)
var wp = wrap.Public().(ed25519.PublicKey)
var node = append([]byte("np"), bytes.Repeat([]byte{11}, 32)...)
var keys = [][]byte{pub}
var authority *tka.Authority

func makeAuthority(ks [][]byte) *tka.Authority {
	state := tka.State{DisablementValues: [][]byte{bytes.Repeat([]byte{1}, 32)}}
	for _, p := range ks {
		state.Keys = append(state.Keys, tka.Key{Kind: tka.Key25519, Public: p, Votes: 1})
	}
	aum := tka.AUM{MessageKind: tka.AUMCheckpoint, State: &state}
	signer := root
	if len(ks) == 1 && bytes.Equal(ks[0], wp) {
		signer = wrap
	}
	h := aum.SigHash()
	aum.Signatures = []tkatype.Signature{{KeyID: tkatype.KeyID(signer.Public().(ed25519.PublicKey)), Signature: ed25519.Sign(signer, h[:])}}
	a, e := tka.Bootstrap(tka.ChonkMem(), aum)
	if e != nil {
		panic(e)
	}
	return a
}
func emit(name string, b []byte) {
	r := row{Name: name, Input: hex.EncodeToString(b), Node: hex.EncodeToString(node[2:])}
	for _, k := range keys {
		r.Keys = append(r.Keys, hex.EncodeToString(k))
	}
	var s tka.NodeKeySignature
	r.Decode = s.Unserialize(b) == nil
	if r.Decode {
		r.Canon = hex.EncodeToString(s.Serialize())
		h := s.SigHash()
		r.Hash = hex.EncodeToString(h[:])
	}
	var n key.NodePublic
	if e := n.UnmarshalBinary(node); e != nil {
		panic(e)
	}
	r.Auth = authority.NodeKeyAuthorized(n, b) == nil
	if e := enc.Encode(r); e != nil {
		panic(e)
	}
}
func sign(s tka.NodeKeySignature, k ed25519.PrivateKey) tka.NodeKeySignature {
	h := s.SigHash()
	s.Signature = ed25519.Sign(k, h[:])
	return s
}
func raw(name, s string) {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	emit(name, b)
}
func main() {
	authority = makeAuthority(keys)
	direct := sign(tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: node, KeyID: pub, WrappingPubkey: wp}, root)
	cred := sign(tka.NodeKeySignature{SigKind: tka.SigCredential, KeyID: pub, WrappingPubkey: wp}, root)
	samples := []tka.NodeKeySignature{direct, cred}
	for _, base := range []tka.NodeKeySignature{direct, cred} {
		s := base
		for depth := 1; depth <= 17; depth++ {
			inner := s
			s = sign(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: node, Nested: &inner}, wrap)
			samples = append(samples, s)
		}
	}
	for i, s := range samples {
		emit(fmt.Sprintf("valid-or-depth-%d", i), s.Serialize())
		if i < 6 {
			b := append([]byte(nil), s.Serialize()...)
			b[2] = 0xe0 | b[2]
			emit(fmt.Sprintf("signed-simple-kind-%d", i), b)
		}
	}
	// Per-byte mutations include signature, identity, bindings, kind and CBOR boundaries.
	rng := rand.New(rand.NewPCG(41, 9))
	for i := range 220 {
		s := samples[rng.IntN(8)]
		b := append([]byte(nil), s.Serialize()...)
		p := rng.IntN(len(b))
		b[p] ^= byte(1 << rng.IntN(8))
		emit(fmt.Sprintf("mutation-%d", i), b)
	}
	b := samples[2].Serialize()
	for i := range b {
		emit(fmt.Sprintf("truncate-%d", i), b[:i])
	}
	for _, v := range []struct{ n, b string }{
		{"empty", ""}, {"null", "f6"}, {"undefined", "f7"}, {"empty-map", "a0"}, {"wrong-root", "80"},
		{"text-kind", "a1613101"}, {"duplicate-alias", "a20101613101"}, {"unknown", "a201011818a201000100"},
		{"unknown-duplicate", "a2181800181801"}, {"unknown-int-collision", "a21bffffffffffffffff002001"},
		{"bad-key-bytes", "a1413101"}, {"bad-key-negative", "a13b800000000000000000"}, {"invalid-key-text", "a161ff01"},
		{"array-bytes", "a202830018fff60382f700"}, {"bad-byte", "a10281190100"}, {"negative-byte", "a1028120"},
		{"bad-kind", "a101190100"}, {"negative-kind", "a10120"}, {"null-kind", "a101f6"}, {"float-kind", "a101f90000"},
		{"max-kind", "a10118ff"},
		{"null-fields", "a601f602f603f604f605f606f6"}, {"wrong-nested", "a10580"}, {"tag", "c0a0"}, {"trailing", "a000"},
		{"noncanonical", "b800"}, {"undefined-kind", "a101f7"}, {"bool-kind", "a101f5"},
	} {
		raw(v.n, v.b)
	}
	for v := range 256 {
		simple := []byte{0xf8, byte(v)}
		if v < 24 {
			simple = []byte{0xe0 | byte(v)}
		}
		emit(fmt.Sprintf("simple-kind-%d", v), append([]byte{0xa1, 1}, simple...))
		emit(fmt.Sprintf("simple-byte-%d", v), append([]byte{0xa1, 2, 0x81}, simple...))
	}
	// Canonical typed reconstruction of alternate byte-slice representations.
	cm, _ := cbor.CTAP2EncOptions().EncMode()
	for i, s := range samples[:6] {
		var obj map[uint64]any
		cbor.Unmarshal(s.Serialize(), &obj)
		for _, field := range []uint64{2, 3, 4, 6} {
			if data, ok := obj[field].([]byte); ok {
				a := make([]uint64, len(data))
				for j, x := range data {
					a[j] = uint64(x)
				}
				obj[field] = a
			}
		}
		obj[99] = map[uint64]any{1: "ignored"}
		b, _ := cm.Marshal(obj)
		emit(fmt.Sprintf("array-fields-%d", i), b)
		for _, field := range []uint64{2, 3, 4, 6} {
			if data, ok := obj[field].([]uint64); ok {
				a := make([]any, len(data))
				for j, x := range data {
					if x <= 19 || x >= 32 {
						a[j] = cbor.SimpleValue(x)
					} else {
						a[j] = x
					}
				}
				obj[field] = a
			}
		}
		b, err := cm.Marshal(obj)
		if err != nil {
			panic(err)
		}
		emit(fmt.Sprintf("signed-simple-byte-fields-%d", i), b)
	}
	bad := direct
	bad.Pubkey = bytes.Repeat([]byte{0}, 34)
	bad = sign(bad, root)
	emit("signed-wrong-node", bad.Serialize())
	bad = direct
	bad.Pubkey = append([]byte("np"), bytes.Repeat([]byte{12}, 32)...)
	bad = sign(bad, root)
	emit("signed-other-node", bad.Serialize())
	bad = direct
	bad.KeyID = wp
	bad = sign(bad, root)
	emit("signed-untrusted-key", bad.Serialize())
	bad = direct
	bad.Nested = &cred
	bad = sign(bad, root)
	emit("signed-direct-nested", bad.Serialize())
	bad = cred
	bad.Pubkey = []byte{1}
	bad = sign(bad, root)
	outer := sign(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: node, Nested: &bad}, wrap)
	emit("credential-pubkey-invalid-details", outer.Serialize())
	bad = cred
	bad.Pubkey = node
	bad = sign(bad, root)
	outer = sign(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: node, Nested: &bad}, wrap)
	emit("credential-pubkey-valid-details", outer.Serialize())
	intermediate := sign(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: node, Nested: &direct, WrappingPubkey: pub}, wrap)
	outer = sign(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: node, Nested: &intermediate}, root)
	emit("overridden-wrapping-key", outer.Serialize())
	outer = sign(outer, wrap)
	emit("wrong-overridden-wrapping-key", outer.Serialize())
	for _, n := range []int{0, 1, 31, 33, 64} {
		bad = direct
		bad.WrappingPubkey = make([]byte, n)
		bad = sign(bad, root)
		outer = sign(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: node, Nested: &bad}, wrap)
		emit(fmt.Sprintf("bad-wrapping-%d", n), outer.Serialize())
	}
	for _, n := range []int{0, 1, 63, 65} {
		bad = direct
		bad.Signature = make([]byte, n)
		emit(fmt.Sprintf("bad-signature-length-%d", n), bad.Serialize())
	}
	// rotationDetails checks nonempty credential Pubkey even after signature verification.
	// ZIP-215 witness: noncanonical identity R accepted by consensus but not strict Go.
	identity := make([]byte, 32)
	identity[0] = 1
	keys = [][]byte{pub, identity}
	authority = makeAuthority(keys)
	sg := make([]byte, 64)
	sg[0] = 0xee
	for j := 1; j < 31; j++ {
		sg[j] = 0xff
	}
	sg[31] = 0x7f
	z := tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: node, KeyID: identity, Signature: sg, WrappingPubkey: identity}
	emit("zip215-direct", z.Serialize())
	cr := tka.NodeKeySignature{SigKind: tka.SigCredential, KeyID: identity, Signature: sg, WrappingPubkey: wp}
	outer = sign(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: node, Nested: &cr}, wrap)
	emit("zip215-credential", outer.Serialize())
	outer = tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: node, Nested: &z, Signature: sg}
	emit("strict-rotation", outer.Serialize())
	// Large fields exercise bounded serialization and decoding at the transport ceiling.
	for _, n := range []int{0, 23, 24, 255, 256, 4096, 65000, 65520, 65529} {
		s := tka.NodeKeySignature{Pubkey: make([]byte, n)}
		emit(fmt.Sprintf("large-%d", n), s.Serialize())
	}
	for _, n := range []int{16, 17, 1000} {
		b := []byte{0xa0}
		for j := 1; j < n; j++ {
			b = append([]byte{0xa1, 5}, b...)
		}
		emit(fmt.Sprintf("depth-%d", n), b)
	}
	for _, n := range []int{4096, 4097} {
		b := []byte{0xa1, 2, 0x99, byte(n >> 8), byte(n)}
		b = append(b, make([]byte, n)...)
		emit(fmt.Sprintf("byte-array-limit-%d", n), b)
	}
	keys = [][]byte{wp}
	authority = makeAuthority(keys)
	emit("authority-key-removed", direct.Serialize())
	keys = nil
	for i := range 511 {
		seed := make([]byte, 32)
		seed[0] = byte(i)
		seed[1] = byte(i >> 8)
		seed[2] = 77
		keys = append(keys, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	keys = append(keys, pub)
	authority = makeAuthority(keys)
	emit("authority-512-last-key", direct.Serialize())
}
