// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Test referee for om/codec, never part of the implementation. Built with go1.26.0, standard
// library only.
//
//	oracle            read driver case lines "OP ARG" on stdin, print Go's result for each
//	oracle corpus     print the hand-made malformed-input corpus as case lines (# lines name groups)
//	oracle rand SEED  print the seeded random differential corpus as case lines
//
// Result lines use the driver's format: encoders "ok TEXT", decoders "ok HEX" or "err", "-" for
// empty.
//
// Third-party code: base32StdNoPad, aumUnmarshalText, parseHex and fromHexChar below are derived
// from tailscale/tailscale tag v1.102.0 (commit 35283c95445fb198af1ce708dac05714bdfaa037), files
// tka/aum.go and types/key/util.go. Copyright (c) 2020 Tailscale Inc & contributors, BSD 3-Clause
// License; the full license text is in TAILSCALE.LICENSE beside this file. Each derived block is
// marked "Derived from tailscale" and ends at "End of tailscale-derived code". Changes from
// upstream: AUMHash is a *[32]byte, parseHex takes strings instead of mem.RO, and parseHex's error
// messages do not format the prefix or sizes. test/gen/tsoracle checks this transcription against
// the real package. Everything else in this file is omnet's own, Apache-2.0.
package main

import (
	"bufio"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
)

// Derived from tailscale v1.102.0 tka/aum.go 24 and 33-41 (BSD-3-Clause, see TAILSCALE.LICENSE).
var base32StdNoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func aumUnmarshalText(h *[32]byte, text []byte) error {
	if ln := base32StdNoPad.DecodedLen(len(text)); ln != len(h) {
		return fmt.Errorf("tka.AUMHash.UnmarshalText: text wrong length: %d, want %d", ln, len(text))
	}
	if _, err := base32StdNoPad.Decode(h[:], text); err != nil {
		return fmt.Errorf("tka.AUMHash.UnmarshalText: %w", err)
	}
	return nil
}

// End of tailscale-derived code.

// Derived from tailscale v1.102.0 types/key/util.go 70-101 (parseHex, fromHexChar), called with the
// prefix "nodekey:" as types/key/node.go 36 and 336-338 do (BSD-3-Clause, see TAILSCALE.LICENSE).
func parseHex(out []byte, in, prefix string) error {
	if !strings.HasPrefix(in, prefix) {
		return errors.New("key hex string doesn't have expected type prefix")
	}
	in = in[len(prefix):]
	if want := len(out) * 2; len(in) != want {
		return errors.New("key hex has the wrong size")
	}
	for i := range out {
		a, ok1 := fromHexChar(in[i*2+0])
		b, ok2 := fromHexChar(in[i*2+1])
		if !ok1 || !ok2 {
			return errors.New("invalid hex character in key")
		}
		out[i] = (a << 4) | b
	}
	return nil
}

func fromHexChar(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// End of tailscale-derived code.

func text(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return string(b)
}

func hx(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func dec(b []byte, err error) string {
	if err != nil {
		return "err"
	}
	return "ok " + hx(b)
}

func result(op string, a []byte) string {
	switch op {
	case "b64e":
		return "ok " + text([]byte(base64.StdEncoding.EncodeToString(a)))
	case "b64d":
		// encoding/json decode.go 950-951: the []byte path of literalStore
		b := make([]byte, base64.StdEncoding.DecodedLen(len(a)))
		n, err := base64.StdEncoding.Decode(b, a)
		return dec(b[:n], err)
	case "b32e":
		return "ok " + text([]byte(base32StdNoPad.EncodeToString(a)))
	case "b32d":
		return dec(base32StdNoPad.DecodeString(string(a)))
	case "hexe":
		return "ok " + text([]byte(hex.EncodeToString(a)))
	case "hexd":
		return dec(hex.DecodeString(string(a)))
	case "aume", "nkye":
		if len(a) != 32 {
			fail("aume/nkye need 32 bytes")
		}
		if op == "aume" {
			return "ok " + base32StdNoPad.EncodeToString(a)
		}
		return "ok nodekey:" + hex.EncodeToString(a)
	case "aumd":
		var h [32]byte
		if aumUnmarshalText(&h, a) != nil {
			return "err"
		}
		return "ok " + hx(h[:])
	case "nkyd":
		var k [32]byte
		if parseHex(k[:], string(a), "nodekey:") != nil {
			return "err"
		}
		return "ok " + hx(k[:])
	}
	fail("unknown op " + op)
	return ""
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "oracle:", msg)
	os.Exit(2)
}

func referee() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		f := strings.Split(in.Text(), " ")
		if len(f) != 2 {
			fail("bad line")
		}
		var a []byte
		if f[1] != "-" {
			var err error
			if a, err = hex.DecodeString(f[1]); err != nil {
				fail("bad hex")
			}
		}
		fmt.Fprintln(out, result(f[0], a))
	}
}

var out = bufio.NewWriter(os.Stdout)

func emit(op string, s []byte) { fmt.Fprintf(out, "%s %s\n", op, hx(s)) }
func emitS(op, s string)       { emit(op, []byte(s)) }
func group(name string)        { fmt.Fprintf(out, "# %s\n", name) }

const (
	b64alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b32alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	hexalpha = "0123456789abcdefABCDEF"
)

// corpus: hand-made cases, one group per malformed-input class of the acceptance list
func corpus() {
	h32 := make([]byte, 32)
	for i := range h32 {
		h32[i] = byte(i*37 + 11)
	}
	aum := base32StdNoPad.EncodeToString(h32)
	nk := "nodekey:" + hex.EncodeToString(h32)

	group("empty input")
	for _, op := range []string{"b64d", "b32d", "hexd", "aumd", "nkyd", "b64e", "b32e", "hexe"} {
		emitS(op, "")
	}

	group("base64: bad characters")
	for _, s := range []string{"Zm9v!", "Zm9v Zm9v", "Zm 9v", "Zm9v\t", "Zm-v", "Zm_v", "Zm9\x00", "Zm9\xff",
		"Zm9\x80", "Zm9v\"", "Zm9v\\", "Zm8=Zm8=", "\x00", " ", "Zm9vYmFy\xffZm9v", "Zm9vYmFyZ!9v",
		"Zm9vYmFyZm9vYmFy-", "====", "Z===", "Zm9vYm=y"} {
		emitS("b64d", s)
	}
	group("base64: wrong padding")
	for _, s := range []string{"Zg", "Zg=", "Zg===", "Zg====", "Zm8", "Zm8==", "Zm9", "Zm9v=", "Zm9v==", "=Zm9v",
		"Z=g=", "Zg=x", "Zm8=x", "Zg==Zg==", "Zg==\n=", "Zg=\n=", "Zg=\r\n=\r\n", "Zm8=\n", "Zm8\n=", "Zg==\nA",
		"Zm9vYg", "Zm9vYg=", "Zm9vYmE", "Zm9vYmE==", "Zm9vYmFy="} {
		emitS("b64d", s)
	}
	group("base64: non-zero trailing bits")
	for _, s := range []string{"Zh==", "Zv==", "Z/==", "Zm9=", "Zm+=", "Zm//", "Zm9vYh==", "Zm9vYmF=", "AB==", "AAB=", "//==", "///="} {
		emitS("b64d", s)
	}
	group("base64: wrong lengths")
	for _, s := range []string{"Z", "Zm", "Zm9", "Zm9vY", "Zm9vYm", "Zm9vYmF", "Zm9vYmFyZ", "A", "AAAAA"} {
		emitS("b64d", s)
	}
	group("base64: mixed case and other alphabets")
	for _, s := range []string{"zM9V", "ZM9V", "Zm9V", "Zm9vYmFy", "ZM9VYMFY", "Zm9v-_8=", "Zm9v+/8="} {
		emitS("b64d", s)
	}
	group("base64: embedded CR/LF")
	for _, s := range []string{"\n", "\r", "\r\n", "\n\n\n\n", "Zm9v\n", "\nZm9v", "Zm\n9v", "Z\rm\n9\r\nv",
		"Zm9v\r\nYmFy", "Zm9vYmFy\n", "Zg=\n=", "Zg\n==", "Zm8\r=", "Zm9v\nYg", "Zm9vYg\n=\n=\n", "Zm9v\n=",
		"\nZ\nm\n9\nv\nY\nm\nF\ny\n", "Zm9vYmFy\r\nZm9vYmFy\r\n"} {
		emitS("b64d", s)
	}

	group("base32: bad characters")
	for _, s := range []string{"MZXW6!", "MZXW 6", "MZXW6\t", "MZXW0", "MZXW1", "MZXW8", "MZXW9", "MZ-W6", "MZXW6\x00",
		"MZXW6\x80", "MZXW6YTB\"", "MZXW6===", "MY======", "MZXQ====", "MZXW6YQ=", "MZXW6YTBOI======", "="} {
		emitS("b32d", s)
	}
	group("base32: padding bytes (= and the NoPadding pad byte 0xff)")
	for _, s := range []string{"MY\xff\xff\xff\xff\xff\xff", "MZXQ\xff\xff\xff\xff", "MZXW6\xff\xff\xff", "MZXW6YQ\xff",
		"MY\xff\xff\xff\xff\xff\xffMY", "MY\xff\xff\xff\xff\xffA", "MY\xff\xff\xff\xff\xff", "M\xff\xff\xff\xff\xff\xff\xff",
		"MZX\xff\xff\xff\xff\xff", "MZXW6Y\xff\xff", "MZ\xff", "MZXW\xff", "\xff", "\xff\xff", "MZXW6YTB\xff",
		"MZXW6YTBMY\xff\xff\xff\xff\xff\xff", "MY\xff\xff\xff\xff\xff\xffAB", "MY\xff\xff\xff\xff\xff\xffABCDEFG",
		"MZXQ\xff\xff\xff\xffZ", "MZXW6\xff\xff\xffQQ", "MY\xff\r\n\xff\xff\xff\xff\xff", "MY\xff\xff\xff\xff\xff\xff\n"} {
		emitS("b32d", s)
	}
	group("base32: non-zero trailing bits")
	for _, s := range []string{"MZ", "M7", "MZXR", "MZX7", "MZXW7", "MZXW6YR", "MZXW6YTBOJ", "MZXW6YTBO7", "77", "7777777"} {
		emitS("b32d", s)
	}
	group("base32: wrong lengths (1, 3 and 6 trailing symbols)")
	for _, s := range []string{"M", "MZX", "MZXW6Y", "MZXW6YTBO", "MZXW6YTBOIM", "MZXW6YTBOIMZXW", "A", "AAA", "AAAAAA",
		"MZXW6YTB", "MZXW6YTBOI"} {
		emitS("b32d", s)
	}
	group("base32: mixed case")
	for _, s := range []string{"mzxw6", "Mzxw6", "MZXw6", "mzxw6ytboi", "MZXW6YTBoi"} {
		emitS("b32d", s)
	}
	group("base32: embedded CR/LF")
	for _, s := range []string{"\n", "\r\n", "MZXW6\n", "\nMZXW6", "MZ\nXW6", "M\rZ\nX\r\nW6", "MZXW6YTB\r\nOI",
		"MZX\nW", "M\nZ", "MZXW6Y\nTBOI\n"} {
		emitS("b32d", s)
	}

	group("hex: bad characters, odd lengths, mixed case")
	for _, s := range []string{"0", "000", "0g", "g0", "zz", "0x00", " 00", "00 ", "0\n", "\n00", "00\r\n", "ABCDEF",
		"abcdef", "aBcDeF", "0123456789abcdefABCDEF", "\xff\xff", "0\x00", "-1", "fG"} {
		emitS("hexd", s)
	}

	group("tka.AUMHash: valid, case, length")
	emitS("aumd", aum)
	emitS("aumd", strings.ToLower(aum))
	emitS("aumd", aum[:51])
	emitS("aumd", aum+"A")
	emitS("aumd", aum[:51]+"=")
	emitS("aumd", aum+"====")
	emitS("aumd", aum[:50]+"Q")
	emitS("aumd", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	emitS("aumd", "7777777777777777777777777777777777777777777777777777")
	emitS("aumd", aum[:51]+"7")
	emitS("aumd", aum[:51]+"1")
	emitS("aumd", aum[:20]+"!"+aum[21:])
	emitS("aumd", base32.StdEncoding.EncodeToString(h32))
	group("tka.AUMHash: CR/LF counted in the length, then stripped")
	emitS("aumd", aum[:51]+"\n")
	emitS("aumd", aum[:50]+"\r\n")
	emitS("aumd", "\n"+aum[:51])
	emitS("aumd", aum[:26]+"\n"+aum[26:51])
	emitS("aumd", aum[:48]+"\n\n\n\n")
	emitS("aumd", aum[:49]+"\n\n\n")
	emitS("aumd", aum[:47]+"\n\n\n\n\n")
	emitS("aumd", aum[:46]+"\n\n\n\n\n\n")
	emitS("aumd", aum[:8]+strings.Repeat("\n", 44))
	emitS("aumd", strings.Repeat("\r\n", 26))
	emitS("aumd", aum[:52]+"\n")
	group("tka.AUMHash: the NoPadding pad byte 0xff")
	emitS("aumd", "MY\xff\xff\xff\xff\xff\xff"+strings.Repeat("\n", 44))
	emitS("aumd", aum[:48]+"MY\xff\xff")
	emitS("aumd", aum[:50]+"\xff\xff")
	emitS("aumd", aum[:40]+"MZXQ\xff\xff\xff\xff"+strings.Repeat("\n", 4))

	group("key.NodePublic: valid, case, prefix, length")
	emitS("nkyd", nk)
	emitS("nkyd", "nodekey:"+strings.ToUpper(hex.EncodeToString(h32)))
	mixed := []byte(nk)
	for i := 8; i < len(mixed); i += 3 {
		if mixed[i] >= 'a' && mixed[i] <= 'f' {
			mixed[i] -= 32
		}
	}
	emit("nkyd", mixed)
	emitS("nkyd", "NODEKEY:"+nk[8:])
	emitS("nkyd", "Nodekey:"+nk[8:])
	emitS("nkyd", "nodekey"+nk[8:])
	emitS("nkyd", "nodekey;"+nk[8:])
	emitS("nkyd", "nodekey: "+nk[9:])
	emitS("nkyd", "discokey:"+nk[8:])
	emitS("nkyd", "mkey:"+nk[8:])
	emitS("nkyd", "privkey:"+nk[8:])
	emitS("nkyd", nk[8:])
	emitS("nkyd", nk[:71])
	emitS("nkyd", nk+"0")
	emitS("nkyd", nk+"00")
	emitS("nkyd", nk+"\n")
	emitS("nkyd", nk[:70])
	emitS("nkyd", "nodekey:")
	emitS("nkyd", "nodekey")
	emitS("nkyd", nk[:71]+"g")
	emitS("nkyd", nk[:8]+"x"+nk[9:])
	emitS("nkyd", nk[:40]+"\n"+nk[41:])
	emitS("nkyd", nk[:40]+" "+nk[41:])
	emitS("nkyd", nk[:71]+"\xff")
	emitS("nkyd", "nodekey:"+strings.Repeat("0", 64))
	emitS("nkyd", "nodekey:"+strings.Repeat("f", 64))
	emitS("nkyd", "nodekey:"+strings.Repeat("F", 64))
	emitS("nkyd", "nodekey:0x"+nk[10:])
}

// interesting bytes for mutations: alphabet characters are added per codec
var noise = []byte("=\r\n \t\x00\x80\xff-_\"\\!.:gGzZ0189+/aA")

func mutate(r *rand.Rand, s []byte, alpha string) []byte {
	pick := func() byte {
		if r.IntN(2) == 0 {
			return alpha[r.IntN(len(alpha))]
		}
		return noise[r.IntN(len(noise))]
	}
	t := append([]byte(nil), s...)
	for range 1 + r.IntN(3) {
		switch k := r.IntN(7); {
		case k == 0 && len(t) > 0:
			t[r.IntN(len(t))] = pick()
		case k == 1:
			i := r.IntN(len(t) + 1)
			t = append(t[:i], append([]byte{pick()}, t[i:]...)...)
		case k == 2 && len(t) > 0:
			i := r.IntN(len(t))
			t = append(t[:i], t[i+1:]...)
		case k == 3 && len(t) > 0:
			t = t[:r.IntN(len(t))]
		case k == 4:
			t = append(t, pick())
		case k == 5 && len(t) > 0:
			// flip the case of one byte
			i := r.IntN(len(t))
			t[i] ^= 32
		case k == 6:
			// a CR or LF somewhere
			i := r.IntN(len(t) + 1)
			t = append(t[:i], append([]byte{"\r\n"[r.IntN(2)]}, t[i:]...)...)
		}
	}
	return t
}

func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// capacity: the largest input each coder takes (encoders 49152, 40960, 32768 bytes; decoders
// 65536 characters), valid and with one bad last character, and 65536 random bytes per decoder
func capacity(r *rand.Rand) {
	big := randBytes(r, 49152)
	emit("b64e", big)
	emit("b32e", big[:40960])
	emit("hexe", big[:32768])
	enc := map[string]string{
		"b64d": base64.StdEncoding.EncodeToString(big),
		"b32d": base32StdNoPad.EncodeToString(big[:40960]),
		"hexd": hex.EncodeToString(big[:32768]),
	}
	for _, op := range []string{"b64d", "b32d", "hexd"} {
		e := []byte(enc[op])
		emit(op, e)
		e[len(e)-1] = '!'
		emit(op, e)
		emit(op, randBytes(r, 65536))
	}
}

// rand: every length 0..2048 for each encoder and the round-trip decode, mutated decoder inputs,
// random garbage, then the capacity edges
func randCorpus(seed uint64) {
	r := rand.New(rand.NewPCG(seed, seed^0x6f6d6e6574))
	for range 300 {
		for _, op := range []string{"b64d", "b32d", "hexd", "aumd", "nkyd"} {
			emit(op, randBytes(r, r.IntN(4097)))
		}
	}
	for n := 0; n <= 2048; n++ {
		b := randBytes(r, n)
		e64 := base64.StdEncoding.EncodeToString(b)
		e32 := base32StdNoPad.EncodeToString(b)
		e16 := hex.EncodeToString(b)
		emit("b64e", b)
		emit("b32e", b)
		emit("hexe", b)
		emitS("b64d", e64)
		emitS("b32d", e32)
		emitS("hexd", e16)
	}
	for range 4000 {
		b := randBytes(r, r.IntN(40))
		emit("b64d", mutate(r, []byte(base64.StdEncoding.EncodeToString(b)), b64alpha))
		emit("b32d", mutate(r, []byte(base32StdNoPad.EncodeToString(b)), b32alpha))
		emit("hexd", mutate(r, []byte(hex.EncodeToString(b)), hexalpha))
	}
	for range 2000 {
		h := randBytes(r, 32)
		a := base32StdNoPad.EncodeToString(h)
		k := "nodekey:" + hex.EncodeToString(h)
		emit("aume", h)
		emit("nkye", h)
		emitS("aumd", a)
		emitS("nkyd", k)
		emit("aumd", mutate(r, []byte(a), b32alpha))
		emit("nkyd", mutate(r, []byte(k), hexalpha))
		// same length, k symbols replaced by CR/LF or by the 0xff pad byte
		m := []byte(a)
		for range 1 + r.IntN(8) {
			m[r.IntN(len(m))] = "\r\n\xff"[r.IntN(3)]
		}
		emit("aumd", m)
	}
	capacity(r)
}

func main() {
	defer out.Flush()
	switch {
	case len(os.Args) == 1:
		referee()
	case len(os.Args) == 2 && os.Args[1] == "corpus":
		corpus()
	case len(os.Args) == 3 && os.Args[1] == "rand":
		seed, err := strconv.ParseUint(os.Args[2], 10, 64)
		if err != nil {
			fail("bad seed")
		}
		randCorpus(seed)
	default:
		fail("usage: oracle [corpus | rand SEED]")
	}
}
