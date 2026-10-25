// SPDX-License-Identifier: Apache-2.0
//
// Cross-check referee for om/codec, never part of the implementation. It calls the real
// tailscale.com v1.102.0 tka.AUMHash and key.NodePublic text methods, so it needs the Go version
// that module requires (go >= 1.26.5). It reads driver case lines whose OP is aume, aumd, nkye or
// nkyd and prints results in the driver format. gen/check-tailscale.sh compares its output with
// gen/oracle, whose transcription of the same functions builds with go1.26.0.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"go4.org/mem"
	"tailscale.com/tka"
	"tailscale.com/types/key"
)

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "tsoracle:", msg)
	os.Exit(2)
}

func hx(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func main() {
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
		switch f[0] {
		case "aume":
			var h tka.AUMHash
			if copy(h[:], a) != 32 || len(a) != 32 {
				fail("aume needs 32 bytes")
			}
			t, _ := h.MarshalText()
			fmt.Fprintln(out, "ok "+string(t))
		case "nkye":
			if len(a) != 32 {
				fail("nkye needs 32 bytes")
			}
			k := key.NodePublicFromRaw32(mem.B(a))
			t, _ := k.MarshalText()
			fmt.Fprintln(out, "ok "+string(t))
		case "aumd":
			var h tka.AUMHash
			if h.UnmarshalText(a) != nil {
				fmt.Fprintln(out, "err")
				continue
			}
			fmt.Fprintln(out, "ok "+hx(h[:]))
		case "nkyd":
			var k key.NodePublic
			if k.UnmarshalText(a) != nil {
				fmt.Fprintln(out, "err")
				continue
			}
			r := k.Raw32()
			fmt.Fprintln(out, "ok "+hx(r[:]))
		default:
			fail("unsupported op " + f[0])
		}
	}
}
