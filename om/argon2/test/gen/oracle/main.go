// SPDX-License-Identifier: Apache-2.0
// Test referee only (never part of the om/argon2 implementation). Reads lines
//   T M P TL PW SALT KEY AD     (decimal, decimal, decimal, decimal, then hex or "-")
//   tka SEC                     (hex or "-")
// and prints the Argon2i tag in lowercase hex, one line per input line.
// Lines without KEY and AD (both "-") use the public golang.org/x/crypto/argon2.Key; lines with a
// secret K or associated data X call the package's internal deriveKey (the function Key wraps)
// through go:linkname, because the public API has no K and X inputs. Both paths are cross-checked
// on every K = X = empty line. "tka SEC" is argon2.Key(SEC, "tailscale network-lock disablement
// salt", 4, 16*1024, 4, 32), the Tailnet Lock disablement value (tailscale tka/disablement.go).
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	_ "unsafe"

	"golang.org/x/crypto/argon2"
)

//go:linkname deriveKey golang.org/x/crypto/argon2.deriveKey
func deriveKey(mode int, password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

const argon2i = 1 // golang.org/x/crypto/argon2: argon2d = 0, argon2i = 1, argon2id = 2

func field(s string) []byte {
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func num(s string) uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		panic(err)
	}
	return uint32(v)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 2 && f[0] == "tka" {
			k := argon2.Key(field(f[1]), []byte("tailscale network-lock disablement salt"), 4, 16*1024, 4, 32)
			fmt.Fprintf(out, "%x\n", k)
			continue
		}
		if len(f) != 8 {
			panic("bad line: " + in.Text())
		}
		t, m, p, tl := num(f[0]), num(f[1]), num(f[2]), num(f[3])
		pw, salt, key, ad := field(f[4]), field(f[5]), field(f[6]), field(f[7])
		k := deriveKey(argon2i, pw, salt, key, ad, t, m, uint8(p), tl)
		if key == nil && ad == nil {
			if pub := argon2.Key(pw, salt, t, m, uint8(p), tl); !bytes.Equal(pub, k) {
				panic("argon2.Key and deriveKey disagree")
			}
		}
		fmt.Fprintf(out, "%x\n", k)
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
