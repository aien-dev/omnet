// SPDX-License-Identifier: Apache-2.0
// Test referee only (never part of the om/ed25519 implementation): reads lines
// "PKHEX SIGHEX MSGHEX" and prints "S C", the results of Go crypto/ed25519.Verify (S)
// and github.com/hdevalence/ed25519consensus.Verify (C), 1 valid / 0 invalid.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/hdevalence/ed25519consensus"
)

func b(v bool) int {
	if v {
		return 1
	}
	return 0
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		f := strings.Split(in.Text(), " ")
		for len(f) < 3 {
			f = append(f, "")
		}
		pk, e1 := hex.DecodeString(f[0])
		sig, e2 := hex.DecodeString(f[1])
		msg, e3 := hex.DecodeString(f[2])
		if e1 != nil || e2 != nil || e3 != nil || len(pk) != 32 || len(sig) != 64 {
			fmt.Fprintln(os.Stderr, "oracle: bad line")
			os.Exit(2)
		}
		fmt.Fprintf(out, "%d %d\n", b(ed25519.Verify(pk, msg, sig)), b(ed25519consensus.Verify(pk, msg, sig)))
	}
}
