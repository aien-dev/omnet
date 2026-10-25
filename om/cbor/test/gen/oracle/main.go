// SPDX-License-Identifier: Apache-2.0
//
// Test referee only (never part of the om/cbor implementation). It writes the committed vector
// files of om/cbor/test/vectors from the real tailscale.com/tka v1.102.0 types and the
// github.com/fxamacker/cbor/v2 v2.9.0 decoder that tka uses.
//
//	oracle gen SEED N      tka-shaped AUM / NodeKeySignature / State structures
//	oracle hostile         the hostile corpus
//	oracle fuzz SEED N     random mutations of generated structures
//	oracle utf8 SEED N     single text strings, valid and invalid UTF-8
//	oracle judge           reads hex lines on stdin, prints "WF AUM NKS" for each
//
// WF is the class of the fxamacker Wellformed error under tka's decoder options (0 = well-formed),
// numbered as om/cbor cbrdec's error codes. AUM and NKS are 1 when tka's own Unserialize accepts
// the bytes into a tka.AUM or a tka.NodeKeySignature.
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2s"
	"tailscale.com/tka"
	"tailscale.com/types/tkatype"
)

// BEGIN derived from tailscale/tailscale v1.102.0 tka/tka.go lines 22-32 (cborDecOpts).
// Copyright (c) 2020 Tailscale Inc & contributors. BSD-3-Clause; the full license text is in
// tailscale.LICENSE in this directory. Changes: renamed to tkaDecOpts, comments replaced.
//
// tkaDecOpts is a copy of tka's cborDecOpts. It is used only for Wellformed (to read the error
// class) and to decode a standalone tka.State, which has no Unserialize method. check() proves the
// copy equal to tka's own decoder on every judged input: whenever Wellformed fails, tka's
// AUM.Unserialize and NodeKeySignature.Unserialize must fail with the same message, because
// Unmarshal runs the same Wellformed check first (fxamacker decode.go 1291-1303).
var tkaDecOpts = cbor.DecOptions{
	DupMapKey:        cbor.DupMapKeyEnforcedAPF,
	IndefLength:      cbor.IndefLengthForbidden,
	TagsMd:           cbor.TagsForbidden,
	MaxNestedLevels:  16,
	MaxArrayElements: 4096,
	MaxMapPairs:      1024,
}

// END derived from tailscale tka/tka.go.

var dec cbor.DecMode
var enc cbor.EncMode

func init() {
	var err error
	if dec, err = tkaDecOpts.DecMode(); err != nil {
		panic(err)
	}
	if enc, err = cbor.CTAP2EncOptions().EncMode(); err != nil {
		panic(err)
	}
}

// code maps an fxamacker well-formedness error to the om/cbor error code.
func code(err error) int {
	if err == nil {
		return 0
	}
	if err == io.EOF {
		return 1
	}
	if err == io.ErrUnexpectedEOF {
		return 2
	}
	var se *cbor.SyntaxError
	if errors.As(err, &se) {
		m := se.Error()
		switch {
		case strings.Contains(m, "invalid additional information"):
			return 3
		case strings.Contains(m, `unexpected "break" code`):
			return 5
		case strings.Contains(m, "invalid simple value"):
			return 7
		}
	}
	var ie *cbor.IndefiniteLengthError
	var te *cbor.TagsMdError
	var ne *cbor.MaxNestedLevelError
	var ae *cbor.MaxArrayElementsError
	var me *cbor.MaxMapPairsError
	var xe *cbor.ExtraneousDataError
	switch {
	case errors.As(err, &ie):
		return 4
	case errors.As(err, &te):
		return 6
	case errors.As(err, &ne):
		return 8
	case errors.As(err, &ae):
		return 9
	case errors.As(err, &me):
		return 10
	case errors.As(err, &xe):
		return 11
	case strings.Contains(err.Error(), "too large"):
		return 12
	}
	panic("oracle: unclassified error: " + err.Error())
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// verdict is what Go says about one input.
type verdict struct {
	wf       int
	aum, nks bool
	aumReser []byte // tka Serialize of the decoded AUM, when aum
	nksReser []byte
}

func check(b []byte) verdict {
	werr := dec.Wellformed(b)
	var a tka.AUM
	aerr := a.Unserialize(b)
	var s tka.NodeKeySignature
	serr := s.Unserialize(b)
	if werr != nil && (aerr == nil || aerr.Error() != werr.Error() || serr == nil || serr.Error() != werr.Error()) {
		panic(fmt.Sprintf("oracle: tka decoder disagrees with the copied options on %x: %v / %v / %v", b, werr, aerr, serr))
	}
	v := verdict{wf: code(werr), aum: aerr == nil, nks: serr == nil}
	if v.aum {
		v.aumReser = a.Serialize()
	}
	if v.nks {
		v.nksReser = s.Serialize()
	}
	return v
}

// ---- random tka-shaped structures ----

type gen struct{ r *rand.Rand }

func (g gen) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(g.r.UintN(256))
	}
	return b
}

// a byte length biased to the head boundaries 0, 23, 24, 255, 256
func (g gen) blen() int {
	switch g.r.IntN(10) {
	case 0:
		return 0
	case 1:
		return 23 + g.r.IntN(3)
	case 2:
		return 254 + g.r.IntN(4)
	case 3:
		return g.r.IntN(80)
	}
	return 32
}

// an unsigned value biased to the head boundaries
func (g gen) uval() uint64 {
	edges := []uint64{0, 1, 23, 24, 255, 256, 65535, 65536, 1<<32 - 1, 1 << 32, 1<<64 - 1}
	switch g.r.IntN(4) {
	case 0:
		return edges[g.r.IntN(len(edges))]
	case 1:
		return g.r.Uint64()
	case 2:
		return g.r.Uint64N(1 << 20)
	}
	return g.r.Uint64N(30)
}

var runes = []rune{'a', 'b', 'z', 'A', '0', ' ', '~', 0x7f, 0x80, 0xfc, 0x7ff, 0x800, 0x6c34, 0xd7ff, 0xe000, 0xfffd, 0xffff, 0x10000, 0x10151, 0x10ffff}

func (g gen) str() string {
	n := g.r.IntN(12)
	if g.r.IntN(8) == 0 {
		n = 20 + g.r.IntN(120)
	}
	var b strings.Builder
	for range n {
		if g.r.IntN(3) == 0 {
			b.WriteRune(runes[g.r.IntN(len(runes))])
		} else {
			b.WriteByte(byte('a' + g.r.IntN(26)))
		}
	}
	return b.String()
}

func (g gen) meta() map[string]string {
	if g.r.IntN(2) == 0 {
		return nil
	}
	n := g.r.IntN(6)
	if g.r.IntN(10) == 0 {
		n = 20 + g.r.IntN(60)
	}
	m := make(map[string]string, n)
	for range n {
		m[g.str()] = g.str()
	}
	return m
}

func (g gen) key() tka.Key {
	return tka.Key{
		Kind:   tka.KeyKind(g.r.IntN(3)),
		Votes:  uint(g.uval()),
		Public: g.bytes(g.blen()),
		Meta:   g.meta(),
	}
}

func (g gen) state(maxKeys int) *tka.State {
	s := &tka.State{StateID1: g.uval(), StateID2: g.uval()}
	if g.r.IntN(4) != 0 {
		h := tka.AUMHash(g.bytes(32))
		s.LastAUMHash = &h
	}
	switch g.r.IntN(3) {
	case 1:
		s.DisablementValues = [][]byte{}
	case 2:
		for i := g.r.IntN(5); i >= 0; i-- {
			s.DisablementValues = append(s.DisablementValues, g.bytes(g.blen()))
		}
	}
	switch g.r.IntN(3) {
	case 1:
		s.Keys = []tka.Key{}
	case 2:
		for i := g.r.IntN(maxKeys); i >= 0; i-- {
			s.Keys = append(s.Keys, g.key())
		}
	}
	return s
}

func (g gen) aum() tka.AUM {
	kinds := []tka.AUMKind{tka.AUMAddKey, tka.AUMRemoveKey, tka.AUMNoOp, tka.AUMUpdateKey, tka.AUMCheckpoint, 0, 6, 255}
	a := tka.AUM{MessageKind: kinds[g.r.IntN(len(kinds))]}
	switch g.r.IntN(4) {
	case 0: // genesis: nil parent
	case 1:
		a.PrevAUMHash = tka.PrevAUMHash(g.bytes(g.blen()))
	default:
		a.PrevAUMHash = tka.PrevAUMHash(g.bytes(32))
	}
	if g.r.IntN(3) == 0 {
		k := g.key()
		a.Key = &k
	}
	if g.r.IntN(3) == 0 {
		a.KeyID = g.bytes(g.blen())
	}
	if g.r.IntN(4) == 0 {
		a.State = g.state(8)
	}
	if g.r.IntN(3) == 0 {
		v := uint(g.uval())
		a.Votes = &v
	}
	a.Meta = g.meta()
	for i := g.r.IntN(4) - 1; i >= 0; i-- {
		a.Signatures = append(a.Signatures, tkatype.Signature{KeyID: g.bytes(32), Signature: g.bytes(64)})
	}
	return a
}

func (g gen) nks(depth int) *tka.NodeKeySignature {
	s := &tka.NodeKeySignature{SigKind: tka.SigKind(g.r.IntN(5))}
	if g.r.IntN(5) != 0 {
		s.Pubkey = g.bytes(32)
	}
	if g.r.IntN(2) == 0 {
		s.KeyID = g.bytes(32)
	}
	if g.r.IntN(5) != 0 {
		s.Signature = g.bytes(64)
	}
	if g.r.IntN(2) == 0 {
		s.WrappingPubkey = g.bytes(32)
	}
	if depth > 1 && g.r.IntN(3) != 0 {
		s.Nested = g.nks(depth - 1)
	}
	return s
}

func h32(b []byte) string {
	s := blake2s.Sum256(b)
	return hex.EncodeToString(s[:])
}

// genLine prints "TYPE HEX HASH K1" after checking that Go itself round-trips the bytes.
func genLine(w io.Writer, typ string, b []byte, hash string, k1 string) {
	v := check(b)
	switch typ {
	case "aum":
		if !v.aum || string(v.aumReser) != string(b) {
			panic("oracle: AUM does not round-trip")
		}
	case "nks":
		if !v.nks || string(v.nksReser) != string(b) {
			panic("oracle: NKS does not round-trip")
		}
	case "state":
		var s tka.State
		if err := dec.Unmarshal(b, &s); err != nil {
			panic(err)
		}
		r, err := enc.Marshal(&s)
		if err != nil || string(r) != string(b) {
			panic("oracle: State does not round-trip")
		}
	}
	if v.wf != 0 || len(b) > 65536 {
		panic("oracle: generated structure not usable")
	}
	fmt.Fprintf(w, "%s %x %s %s\n", typ, b, hash, k1)
}

func cmdGen(w io.Writer, seed uint64, n int) {
	g := gen{rand.New(rand.NewPCG(seed, 8949))}
	for i := range n {
		switch {
		case i%12 < 7:
			a := g.aum()
			if i == 7*12 { // one checkpoint at tka's 512-key limit (state.go staticValidateCheckpoint)
				a.State = g.state(1)
				a.State.Keys = nil
				for len(a.State.Keys) < 512 {
					a.State.Keys = append(a.State.Keys, tka.Key{Kind: tka.Key25519, Votes: 1, Public: g.bytes(32)})
				}
			}
			b := a.Serialize()
			h := a.Hash()
			if hex.EncodeToString(h[:]) != h32(b) {
				panic("oracle: AUM.Hash is not BLAKE2s-256 of Serialize")
			}
			genLine(w, "aum", b, hex.EncodeToString(h[:]), "0:"+strconv.Itoa(int(a.MessageKind)))
		case i%12 < 10:
			s := g.nks(15) // root plus 14 nested maps at most: depth <= 15
			b := s.Serialize()
			genLine(w, "nks", b, h32(b), "0:"+strconv.Itoa(int(s.SigKind)))
		default:
			s := g.state(12)
			b, err := enc.Marshal(s)
			if err != nil {
				panic(err)
			}
			k1 := "7:22" // LastAUMHash nil encodes as null
			if s.LastAUMHash != nil {
				k1 = "2:32"
			}
			genLine(w, "state", b, h32(b), k1)
		}
	}
}

// ---- hostile corpus ----

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func cat(parts ...[]byte) []byte {
	var o []byte
	for _, p := range parts {
		o = append(o, p...)
	}
	return o
}

func rep(b []byte, n int) []byte {
	var o []byte
	for range n {
		o = append(o, b...)
	}
	return o
}

// addPairs returns root map m (fewer than 24 pairs, one-byte head) with extra pairs appended.
func addPairs(m []byte, k int, pairs ...[]byte) []byte {
	if m[0] < 0xa0 || m[0]+byte(k) > 0xb7 {
		panic("oracle: addPairs needs a small map")
	}
	return cat([]byte{m[0] + byte(k)}, m[1:], cat(pairs...))
}

type hcase struct {
	class, target string
	b             []byte
	desc          string
}

func baseAUM() []byte {
	a := tka.AUM{
		MessageKind: tka.AUMAddKey,
		PrevAUMHash: tka.PrevAUMHash(rep([]byte{0x11}, 32)),
		Key:         &tka.Key{Kind: tka.Key25519, Votes: 2, Public: rep([]byte{0x22}, 32), Meta: map[string]string{"name": "a"}},
		Signatures:  []tkatype.Signature{{KeyID: rep([]byte{0x22}, 32), Signature: rep([]byte{0x33}, 64)}},
	}
	return a.Serialize()
}

func nestedNKS(levels int) []byte {
	var s *tka.NodeKeySignature
	for i := range levels {
		s = &tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: rep([]byte{byte(i)}, 32), Nested: s}
	}
	s.SigKind = tka.SigRotation
	return s.Serialize()
}

func hostile() []hcase {
	base := baseAUM()
	nks := nestedNKS(3)
	var cs []hcase
	add := func(class, target string, b []byte, desc string) {
		cs = append(cs, hcase{class, target, b, desc})
	}
	u99 := mustHex("1863") // unknown key 99
	unk := func(v []byte) []byte { return addPairs(base, 1, u99, v) }

	add("W", "aum", nil, "empty input")
	for i := 1; i < len(base); i++ {
		add("W", "aum", base[:i], fmt.Sprintf("base AUM truncated to %d of %d bytes", i, len(base)))
	}
	for i := 1; i < len(nks); i++ {
		add("W", "nks", nks[:i], fmt.Sprintf("base NKS truncated to %d of %d bytes", i, len(nks)))
	}
	add("W", "aum", base, "base AUM (control)")
	add("W", "nks", nks, "base NKS (control)")
	add("W", "aum", cat(base, []byte{0}), "one byte after the AUM")
	add("W", "aum", cat(base, base), "two AUMs back to back")
	add("W", "aum", cat(base, []byte{0xff}), "break code after the AUM")

	// huge or false declared lengths in a skipped value
	for _, h := range []string{"5bffffffffffffffff", "5b8000000000000000", "5b7fffffffffffffff", "5b0000000100000000", "5a00010000", "59ffff", "58ff", "5801",
		"7bffffffffffffffff", "7b8000000000000000", "7a00010000", "9bffffffffffffffff", "9b8000000000000000", "9a00010000", "991001", "991000",
		"bbffffffffffffffff", "bb8000000000000000", "b90401", "b90400", "1b", "1a0000", "19ff", "18"} {
		add("W", "aum", unk(mustHex(h)), "skipped value with head "+h+" and no content")
	}
	add("W", "aum", unk(cat(mustHex("991000"), rep([]byte{0}, 4096))), "skipped array of 4096 elements (the limit)")
	add("W", "aum", unk(cat(mustHex("991001"), rep([]byte{0}, 4097))), "skipped array of 4097 elements")
	var m1024 []byte
	for i := range 1024 {
		m1024 = append(m1024, 0x19, byte(i>>8), byte(i), 0)
	}
	add("W", "aum", unk(cat(mustHex("b90400"), m1024)), "skipped map of 1024 pairs (the limit)")
	add("W", "aum", unk(cat(mustHex("b90401"), m1024, mustHex("1a0001000000"))), "skipped map of 1025 pairs")
	add("W", "aum", unk(cat(mustHex("5a00000004"), mustHex("01020304"))), "skipped byte string with a 4-byte length head")

	// nesting depth: the root map is level 1
	for _, n := range []int{14, 15, 16, 40, 2000} {
		add("W", "aum", unk(cat(rep([]byte{0x81}, n), []byte{0x80})), fmt.Sprintf("skipped value: %d nested arrays (depth %d)", n+1, n+2))
		add("W", "aum", unk(cat(rep([]byte{0xa1, 0x00}, n), []byte{0xa0})), fmt.Sprintf("skipped value: %d nested maps (depth %d)", n+1, n+2))
	}
	add("W", "aum", unk(cat(rep([]byte{0x81}, 15), []byte{0x9f, 0xff})), "indefinite array at depth 17")
	add("W", "aum", unk(cat(rep([]byte{0x81}, 14), []byte{0x9f, 0xff})), "indefinite array at depth 16")
	add("W", "nks", nestedNKS(16), "NodeKeySignature nested 16 deep (tka types, depth 16)")
	add("W", "nks", nestedNKS(17), "NodeKeySignature nested 17 deep (tka types, depth 17)")
	add("W", "aum", cat(rep([]byte{0x81}, 3000), []byte{0x80}), "3001 nested arrays at the root")

	// indefinite lengths
	for _, h := range []string{"5fff", "7fff", "9fff", "bfff", "5f410000ff", "7f6161ff", "9f00ff", "bf0000ff", "5f", "9f"} {
		add("W", "aum", unk(mustHex(h)), "skipped indefinite-length item "+h)
	}
	add("W", "aum", cat([]byte{0xbf}, base[1:], []byte{0xff}), "the AUM as an indefinite-length map")
	{
		pb := mustHex("025f582011111111111111111111111111111111111111111111111111111111111111ff")
		i := strings.Index(hex.EncodeToString(base), "025820")
		if i < 0 || i%2 != 0 {
			panic("oracle: PrevAUMHash not found")
		}
		j := i/2 + 3 + 32
		add("W", "aum", cat(base[:i/2], pb, base[j:]), "PrevAUMHash as an indefinite byte string of one chunk")
	}

	// tags
	for _, h := range []string{"c000", "c11a514b67b0", "d818456449455446", "c249010000000000000000", "c0c000", "d9d9f700", "dbffffffffffffffff00", "d9", "c0"} {
		add("W", "aum", unk(mustHex(h)), "skipped tagged item "+h)
	}
	add("W", "aum", cat([]byte{0xd8, 0x18}, base), "the AUM wrapped in tag 24")

	// reserved additional information and break codes
	for m := range 8 {
		for _, ai := range []int{28, 29, 30} {
			add("W", "aum", unk([]byte{byte(m<<5 | ai)}), fmt.Sprintf("skipped head: major %d additional information %d", m, ai))
		}
	}
	for _, h := range []string{"1f", "3f", "df", "ff"} {
		add("W", "aum", unk(mustHex(h)), "skipped head "+h+" (additional information 31)")
	}
	add("W", "aum", mustHex("ff"), "a lone break code")
	add("W", "aum", mustHex("1c"), "a lone reserved head")

	// simple values and floats (accepted by Go when skipped)
	for _, h := range []string{"f800", "f813", "f81f", "f820", "f8ff", "e0", "f3", "f7", "f4", "f5", "f6",
		"f90000", "f97e00", "f97c00", "fa7fc00000", "fb7ff8000000000000", "fbfff0000000000000", "f9", "fa0000", "fb00"} {
		add("W", "aum", unk(mustHex(h)), "skipped simple value or float "+h)
	}
	// form the decoder does not check in skipped values
	add("W", "aum", unk(mustHex("a2020101010202")), "skipped map with unsorted keys")
	add("W", "aum", unk(mustHex("a201000100")), "skipped map with a duplicate key (Go does not check skipped values)")
	add("W", "aum", unk(mustHex("62c328")), "skipped text string with invalid UTF-8 (Go does not check skipped values)")
	add("W", "aum", unk(mustHex("1b0000000000000001")), "skipped integer in non-shortest form")
	add("W", "aum", addPairs(base, 1, mustHex("627a7a"), mustHex("00")), "unknown text key \"zz\"")
	add("W", "aum", addPairs(base, 1, mustHex("38ff"), mustHex("00")), "unknown negative key -256")

	// duplicate keys at the root (APF: Go rejects every duplicate in a struct map)
	add("D", "aum", addPairs(base, 1, mustHex("01"), mustHex("03")), "MessageKind key 1 twice")
	add("D", "aum", addPairs(base, 1, mustHex("1801"), mustHex("03")), "key 1 twice, once as 0x1801")
	add("D", "aum", addPairs(base, 2, u99, mustHex("00"), u99, mustHex("01")), "unknown key 99 twice")
	add("D", "aum", addPairs(base, 2, mustHex("627a7a"), mustHex("00"), mustHex("627a7a"), mustHex("00")), "unknown text key \"zz\" twice")
	add("D", "aum", addPairs(base, 2, mustHex("1bffffffffffffffff"), mustHex("00"), mustHex("20"), mustHex("00")), "keys 2^64-1 and -1: both int64 -1 in Go")
	add("D", "nks", addPairs(nks, 1, mustHex("01"), mustHex("02")), "NKS SigKind twice")

	// invalid UTF-8 where Go decodes a text string (Meta)
	add("U", "aum", mustHex("a3010302f607a161616261ff"), "NoOp AUM with Meta value \"a\\xff\"")
	add("U", "aum", mustHex("a3010302f607a162c3286161"), "NoOp AUM with Meta key \"\\xc3(\"")
	add("U", "aum", mustHex("a3010302f607a1616163eda080"), "NoOp AUM with a surrogate (ED A0 80) in a Meta value")

	// non-canonical but accepted: Go's re-serialization is canonical
	add("R", "aum", mustHex("a2011803 02f6"), "MessageKind 3 as 0x1803")
	add("R", "aum", mustHex("a201190003 02f6"), "MessageKind 3 as 0x190003")
	add("R", "aum", mustHex("a2011a00000003 02f6"), "MessageKind 3 as 0x1a00000003")
	add("R", "aum", mustHex("a2011b0000000000000003 02f6"), "MessageKind 3 as 0x1b0000000000000003")
	add("R", "aum", mustHex("b80201 03 02f6"), "root map count as 0xb802")
	add("R", "aum", mustHex("b9000201 03 02f6"), "root map count as 0xb90002")
	add("R", "aum", mustHex("a202f60103"), "root keys in the order 2, 1")
	add("R", "aum", mustHex("a3 07a1616161 62 0103 02f6"), "root keys in the order 7, 1, 2")
	add("R", "aum", cat(mustHex("a301030259 0020"), rep([]byte{0x11}, 32), mustHex("06 1b0000000000000005")), "PrevAUMHash length as 0x590020, Votes 5 as 0x1b0000000000000005")
	add("R", "aum", mustHex("a3010302f607a3 626262 6131 6161 6132 6162 6133"), "Meta keys \"bb\", \"a\", \"b\" (CTAP2 order is a, b, bb)")
	add("R", "aum", mustHex("a3010302f607a2 780161 6131 780162 6132"), "Meta keys with 0x7801 heads")
	add("R", "aum", cat(mustHex("a3010302f6179801a2"), mustHex("015820"), rep([]byte{0x22}, 32), mustHex("025840"), rep([]byte{0x33}, 64)), "Signatures array head 0x9801")
	add("R", "aum", cat(mustHex("a3010302f61781a2"), mustHex("025840"), rep([]byte{0x33}, 64), mustHex("015820"), rep([]byte{0x22}, 32)), "Signature keys in the order 2, 1")
	add("R", "nks", mustHex("a2 02 41aa 01 01"), "NKS keys in the order 2, 1")
	add("R", "nks", mustHex("a2 01 02 05 a2 02 41bb 01 1801"), "NKS with a nested NKS whose keys are unsorted and non-shortest")
	add("R", "aum", mustHex("a3 01 05 02 f6 05 a5 03 80 01 f6 05 01 02 80 04 1b0000000000000007"), "Checkpoint with State keys unsorted and StateID1 non-shortest")

	// typed rejections: well-formed CBOR that tka's struct decoding refuses (model-layer duties)
	add("T", "aum", mustHex("00"), "root is an integer, not a map")
	add("T", "aum", mustHex("80"), "root is an array")
	add("T", "aum", mustHex("a2016178 02f6"), "MessageKind as a text string")
	add("T", "aum", mustHex("a201190100 02f6"), "MessageKind 256 overflows uint8")
	add("T", "aum", mustHex("a20120 02f6"), "MessageKind -1")
	add("T", "aum", mustHex("a3010302f60620"), "Votes -1")
	add("Q", "aum", mustHex("a201030281 00"), "PrevAUMHash as the array [0]: fxamacker fills a []byte from an array of integers")
	add("T", "aum", mustHex("a3010302f64101 00"), "byte-string map key")
	add("T", "aum", mustHex("a3010302f6 3bffffffffffffffff 00"), "negative key below -2^63")
	add("T", "aum", mustHex("a3010302f607a2 6161 6178 6161 6179"), "duplicate Meta key \"a\" (map[string]string)")
	add("Q", "aum", mustHex("a3010302f607a16161f6"), "Meta value null decodes to the empty string")
	add("T", "aum", mustHex("a3010302f603a3010102f9000003f6"), "Key.Votes as a float")
	// quirks: Go accepts and the canonical re-encoding differs from Go's typed re-serialization
	add("Q", "aum", mustHex("a2613103 02f6"), "text key \"1\" matches the field named 1 (cache.go 139-145)")
	add("Q", "aum", mustHex("a3010302f61863f6"), "unknown key 99 is dropped by Go's re-serialization")
	add("Q", "aum", mustHex("a3010302f603f6"), "Key null decodes to a nil *Key, omitted on re-serialization")
	return cs
}

func cmdHostile(w io.Writer) {
	for _, c := range hostile() {
		v := check(c.b)
		acc, reser := v.aum, v.aumReser
		if c.target == "nks" {
			acc, reser = v.nks, v.nksReser
		}
		ok := true
		switch c.class {
		case "W":
			ok = (v.wf == 0) == acc
		case "D", "U", "T":
			ok = v.wf == 0 && !acc
		case "R":
			ok = acc && string(reser) != string(c.b)
		case "Q":
			ok = acc
		}
		if !ok {
			panic(fmt.Sprintf("oracle: hostile case %q (%s) does not fit its class: wf %d accept %v", c.desc, c.class, v.wf, acc))
		}
		h, rs := hex.EncodeToString(c.b), "-"
		if h == "" {
			h = "-"
		}
		if acc {
			rs = hex.EncodeToString(reser)
		}
		fmt.Fprintf(w, "%s %s %d %d %s %s %s\n", c.class, c.target, v.wf, b2i(acc), rs, h, c.desc)
	}
}

// ---- fuzz: mutations of generated structures ----

func cmdFuzz(w io.Writer, seed uint64, n int) {
	r := rand.New(rand.NewPCG(seed, 7049))
	g := gen{r}
	for i := range n {
		var b []byte
		if i%3 == 2 {
			b = g.nks(4).Serialize()
		} else {
			a := g.aum() // kept small: at most one State key, short Meta
			if a.State != nil && len(a.State.Keys) > 1 {
				a.State.Keys = a.State.Keys[:1]
			}
			if len(a.Meta) > 2 {
				a.Meta = map[string]string{"n": "v", "nn": "vv"}
			}
			if a.Key != nil {
				a.Key.Meta = nil
			}
			b = a.Serialize()
		}
		for k := 1 + r.IntN(3); k > 0 && len(b) > 0; k-- {
			p := r.IntN(len(b))
			switch r.IntN(6) {
			case 0:
				b[p] ^= byte(1 << r.IntN(8))
			case 1:
				b[p] = byte(r.UintN(256))
			case 2:
				b = b[:p]
			case 3:
				b = cat(b[:p], []byte{byte(r.UintN(256))}, b[p:])
			case 4:
				b = cat(b[:p], b[p+1:])
			case 5:
				specials := []byte{0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1f, 0x5f, 0x7f, 0x9f, 0xbf, 0xc0, 0xd8, 0xf8, 0xf9, 0xfb, 0xff}
				b[p] = specials[r.IntN(len(specials))]
			}
		}
		v := check(b)
		h := hex.EncodeToString(b)
		if h == "" {
			h = "-"
		}
		fmt.Fprintf(w, "%d %d %d %s\n", v.wf, b2i(v.aum), b2i(v.nks), h)
	}
}

// ---- UTF-8: single text strings ----

func cmdUTF8(w io.Writer, seed uint64, n int) {
	r := rand.New(rand.NewPCG(seed, 3629))
	interesting := []byte{0x00, 0x41, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf3, 0xf4, 0xf5, 0xff}
	for i := range n {
		l := r.IntN(9)
		b := make([]byte, l)
		for j := range b {
			b[j] = interesting[r.IntN(len(interesting))]
		}
		if i%4 == 0 { // a random valid rune somewhere
			b = utf8.AppendRune(b, rune(r.IntN(0x110000)))
		}
		item, err := enc.Marshal(string(b))
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(w, "%d %x\n", b2i(utf8.Valid(b)), item)
	}
}

func cmdJudge(in io.Reader, w io.Writer) {
	s := bufio.NewScanner(in)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		f := strings.Fields(s.Text())
		var b []byte
		if len(f) > 0 && f[0] != "-" {
			b = mustHex(f[0])
		}
		v := check(b)
		fmt.Fprintf(w, "%d %d %d\n", v.wf, b2i(v.aum), b2i(v.nks))
	}
}

func main() {
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	arg := func(i int) uint64 {
		v, err := strconv.ParseUint(os.Args[i], 10, 64)
		if err != nil {
			panic(err)
		}
		return v
	}
	switch os.Args[1] {
	case "gen":
		cmdGen(out, arg(2), int(arg(3)))
	case "hostile":
		cmdHostile(out)
	case "fuzz":
		cmdFuzz(out, arg(2), int(arg(3)))
	case "utf8":
		cmdUTF8(out, arg(2), int(arg(3)))
	case "judge":
		cmdJudge(os.Stdin, out)
	default:
		fmt.Fprintln(os.Stderr, "usage: oracle gen SEED N | hostile | fuzz SEED N | utf8 SEED N | judge")
		os.Exit(2)
	}
}
