// SPDX-License-Identifier: Apache-2.0
// Test-only oracle: encoding/json and actual tailscale.com v1.102.0 tailcfg types.
package main

import (
 "bytes"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "math/rand/v2"
 "os"
 "regexp"
 "strconv"
 "strings"
 "tailscale.com/tailcfg"
)

type token struct { fields [7]uint64; data []byte }
type parser struct { dec *json.Decoder; tok []token; used int }
func (p *parser) value(parent, key uint64, depth int) error {
 if len(p.tok) == 4095 { return fmt.Errorf("tokens") }
 v, err := p.dec.Token(); if err != nil { return err }
 id := len(p.tok)+1
 t := token{fields:[7]uint64{0,uint64(p.used),0,uint64(id+1),parent,0,key}}
 switch x:=v.(type) {
 case json.Delim:
  if x!='{' && x!='[' { return fmt.Errorf("delimiter") }
  if depth == 32 { return fmt.Errorf("depth") }
  t.fields[0]=1; if x=='[' {t.fields[0]=2}
  p.tok=append(p.tok,t)
  seen:=map[string]bool{}
  for p.dec.More() {
   if x=='{' {
    if len(seen)==256{return fmt.Errorf("members")}
    k,err:=p.dec.Token(); if err!=nil{return err}; s,ok:=k.(string); if !ok{return fmt.Errorf("key")}
    if seen[s] {return fmt.Errorf("duplicate")}; seen[s]=true
    if len(p.tok)==4095{return fmt.Errorf("tokens")}
    kid:=len(p.tok)+1
    p.tok=append(p.tok,token{[7]uint64{3,uint64(p.used),uint64(len(s)),uint64(kid+1),uint64(id),0,1},[]byte(s)})
    p.used+=len(s); if p.used>65536{return fmt.Errorf("bytes")}
    p.tok[id-1].fields[5]++
   }
   if err:=p.value(uint64(id),0,depth+1);err!=nil{return err}
   p.tok[id-1].fields[5]++
  }
  close,err:=p.dec.Token(); if err!=nil{return err}
  want:=json.Delim('}'); if x=='['{want=']'}; if close!=want{return fmt.Errorf("close")}
  p.tok[id-1].fields[3]=uint64(len(p.tok)+1)
  return nil
 case string: t.fields[0]=3; t.data=[]byte(x)
 case json.Number: t.fields[0]=4; t.data=[]byte(x.String())
 case bool: t.fields[0]=6; if x {t.fields[0]=5}
 case nil: t.fields[0]=7
 default: return fmt.Errorf("unexpected token")
 }
 t.fields[2]=uint64(len(t.data)); p.used+=len(t.data)
 if p.used>65536{return fmt.Errorf("bytes")}
 p.tok=append(p.tok,t)
 return nil
}
func (p *parser) encoded(id int) []byte {
 t:=p.tok[id-1]
 switch t.fields[0] {
 case 1,2:
  obj:=t.fields[0]==1; var b bytes.Buffer
  if obj {b.WriteByte('{')} else {b.WriteByte('[')}
  i:=id+1
  for i<int(t.fields[3]) {
   if i>id+1 {b.WriteByte(',')}
   if obj {s,_:=json.Marshal(string(p.tok[i-1].data));b.Write(s);b.WriteByte(':');i++}
   b.Write(p.encoded(i));i=int(p.tok[i-1].fields[3])
  }
  if obj {b.WriteByte('}')} else {b.WriteByte(']')};return b.Bytes()
 case 3: b,_:=json.Marshal(string(t.data));return b
 case 4:return t.data
 case 5:return []byte("true")
 case 6:return []byte("false")
 default:return []byte("null")
 }
}
var uintRE=regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var intRE=regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
func expected(mode string, raw []byte) string {
 switch mode {
 case "P":
  if len(raw)==0 || len(raw)>65536{return "E"}
  p:=parser{dec:json.NewDecoder(bytes.NewReader(raw))};p.dec.UseNumber()
  if p.value(0,0,0)!=nil{return "E"}
  if _,e:=p.dec.Token();e!=io.EOF{return "E"}
  h:=uint64(14695981039346656037)
  for _,t:=range p.tok {for _,v:=range t.fields{h=(h^v)*1099511628211};for _,v:=range t.data{h=(h^uint64(v))*1099511628211}}
  b:=p.encoded(1);encoded:=hex.EncodeToString(b);if len(b)>65536{encoded="!"}
  return fmt.Sprintf("O %d %s",h,encoded)
 case "Q":
  b,_:=json.Marshal(string(raw));if len(b)>65536{return "E"};return "O "+hex.EncodeToString(b)
 case "U":
  if !uintRE.Match(raw){return "E"};var v uint64;if json.Unmarshal(raw,&v)!=nil{return "E"};return "O "+strconv.FormatUint(v,10)
 case "I":
  if !intRE.Match(raw){return "E"};var v int64;if json.Unmarshal(raw,&v)!=nil{return "E"};return "O "+strconv.FormatInt(v,10)
 }
 panic(mode)
}
type row struct { Class string `json:"class"`; Mode string `json:"mode"`; Hex string `json:"hex"`; Want string `json:"want"` }
var enc=json.NewEncoder(os.Stdout)
func emit(class,mode string,raw []byte){if len(raw)>65536{panic("oversized driver record")};if err:=enc.Encode(row{class,mode,hex.EncodeToString(raw),expected(mode,raw)});err!=nil{panic(err)}}
func typed(name,raw string,v any){if err:=json.Unmarshal([]byte(raw),v);err!=nil{panic(fmt.Sprintf("%s: %v",name,err))};emit("tailcfg-"+name,"P",[]byte(raw));b,e:=json.Marshal(v);if e!=nil{panic(e)};emit("tailcfg-"+name+"-marshal","P",b)}
func tailcfgCases(){
 nk:="nodekey:"+strings.Repeat("01",32)
 base:=`"Version":106,"NodeKey":"`+nk+`"`
 typed("init-begin",`{`+base+`,"GenesisAUM":"AAECA/8="}`,&tailcfg.TKAInitBeginRequest{})
 typed("init-finish",`{`+base+`,"Signatures":{"9007199254740993":"AAE=","9223372036854775807":null},"SupportDisablement":""}`,&tailcfg.TKAInitFinishRequest{})
 typed("bootstrap",`{`+base+`,"Head":""}`,&tailcfg.TKABootstrapRequest{})
 typed("sync-offer",`{`+base+`,"Head":"A","Ancestors":["B","C"]}`,&tailcfg.TKASyncOfferRequest{})
 typed("sync-send",`{`+base+`,"Head":"A","MissingAUMs":["AAE=",null,""],"Interactive":true}`,&tailcfg.TKASyncSendRequest{})
 typed("disable",`{`+base+`,"Head":"A","DisablementSecret":"AAE="}`,&tailcfg.TKADisableRequest{})
 typed("sign",`{`+base+`,"Signature":"AAE="}`,&tailcfg.TKASubmitSignatureRequest{})
 typed("affected",`{`+base+`,"KeyID":"AAE="}`,&tailcfg.TKASignaturesUsingKeyRequest{})
 typed("begin-response",`{"NeedSignatures":[{"NodeID":9007199254740993,"NodePublic":"`+nk+`","RotationPubkey":"AAE="}]}`,&tailcfg.TKAInitBeginResponse{})
 typed("bootstrap-response",`{"GenesisAUM":"AAE=","DisablementSecret":"AAE="}`,&tailcfg.TKABootstrapResponse{})
 typed("offer-response",`{"Head":"A","Ancestors":["B"],"MissingAUMs":["AAE=",null,""]}`,&tailcfg.TKASyncOfferResponse{})
 typed("send-response",`{"Head":"A"}`,&tailcfg.TKASyncSendResponse{})
 typed("affected-response",`{"Signatures":["AAE=",null,""]}`,&tailcfg.TKASignaturesUsingKeyResponse{})
 typed("finish-response",`{}`,&tailcfg.TKAInitFinishResponse{})
 typed("disable-response",`{}`,&tailcfg.TKADisableResponse{})
 typed("sign-response",`{}`,&tailcfg.TKASubmitSignatureResponse{})
 typed("map-info",`{"Head":"A","Disabled":true}`,&tailcfg.TKAInfo{})
 typed("case-insensitive",`{"vErSiOn":106,"nodekey":"`+nk+`","GenesisAUM":null}`,&tailcfg.TKAInitBeginRequest{})
 typed("byte-array",`{`+base+`,"GenesisAUM":[0,1,2,255]}`,&tailcfg.TKAInitBeginRequest{})
 typed("null-optionals",`{"Version":null,"NodeKey":null,"Head":null,"Ancestors":null}`,&tailcfg.TKASyncOfferRequest{})
 typed("escaped-key",`{"\u0056ersion":106,"NodeKey":"`+nk+`","GenesisAUM":"AA\nE="}`,&tailcfg.TKAInitBeginRequest{})
 typed("unknown-field",`{`+base+`,"GenesisAUM":"","Future":{"x":[1,true,null]}}`,&tailcfg.TKAInitBeginRequest{})
 for _,field:=range []string{`"Version":1.0`,`"Version":9223372036854775808`,`"GenesisAUM":true`,`"GenesisAUM":"?"`,`"GenesisAUM":[256]`,`"NodeKey":"bad"`} {
  raw:=[]byte(`{`+field+`}`);var v tailcfg.TKAInitBeginRequest
  if json.Unmarshal(raw,&v)==nil{panic("expected typed rejection")}
  emit("tailcfg-syntax-not-schema","P",raw)
 }
}
func randomBytes(r *rand.Rand, n int) []byte { b:=make([]byte,n);for i:=range b{b[i]=byte(r.Uint64())};return b }
func randomValue(r *rand.Rand, depth int) any {
 k:=r.IntN(7);if depth==4{k=r.IntN(5)}
 switch k {
 case 0:return nil
 case 1:return r.IntN(2)==1
 case 2:return json.Number(fmt.Sprintf("%d",r.Uint64()))
 case 3:return json.Number(fmt.Sprintf("-%de-%d",r.IntN(100000),r.IntN(1000)))
 case 4:return string(randomBytes(r,r.IntN(40)))
 case 5:a:=make([]any,r.IntN(6));for i:=range a{a[i]=randomValue(r,depth+1)};return a
 default:a:=map[string]any{};for i:=range r.IntN(6){a[fmt.Sprintf("key%d",i)]=randomValue(r,depth+1)};return a
 }
}
func main(){
 tailcfgCases()
 valid:=[]string{`null`,`true`,`false`,`0`,`-0`,`18446744073709551615`,`-9223372036854775808`,`9007199254740993`,`1.234567890123456789e+999999`,`[]`,`{}`,`{"a":[],"b":{},"c":[1,{"d":2}],"e":false}`,`"\"\\\/\b\f\n\r\t"`,`"\u0000\u001f\u007f"`,`"\ud800\udc00\udbff\udfff"`,`"\ud800x\udc00\ud800\ud800"`,`"\u2028\u2029<>&"`,`"\uD834\uDd1E"`,`{"A":1,"a":2}`," \r\n\t[1, 2]\n"}
 for _,s:=range valid{emit("grammar","P",[]byte(s))}
 invalid:=[]string{""," ","+1","01","-01","--1","1.",".1","1e","1e+","1e-","NaN","Infinity","truefalse","null null","[1,]","[,1]","[1 2]","{,}","{\"a\":}","{\"a\":1,}","{1:2}","{\"a\" 2}","{\"a\":1 \"b\":2}","\"\\x00\"","\"\\u12\"","\"\\uZZZZ\"","\"a\nb\"","\"","\"abc\\","[","{","\ufeff{}","\x00","[true,false,null}",`"\ud800\u12xx"`}
 for _,s:=range invalid{emit("malformed","P",[]byte(s))}
 for _,s:=range []string{`{"a":1,"a":2}`,`{"a":1,"\u0061":2}`,`{"x":{"a":1,"a":2}}`,`{"\ud800":0,"\udc00":1}`,`{"a":{},"a":[]}`} {emit("duplicate-policy","P",[]byte(s))}
 for i:=range 256 {emit("byte-quote","Q",[]byte{byte(i)});emit("byte-string","P",[]byte{'"',byte(i),'"'})}
 for _,b:=range [][]byte{{0xc0,0x80},{0xe0,0x80,0x80},{0xed,0xa0,0x80},{0xf4,0x90,0x80,0x80},{0xf0,0x80,0x80,0x80},{0xe2,0x82},{0xef,0xbf,0xbd},{0xf0,0x90,0x80,0x80},{0xf4,0x8f,0xbf,0xbf}} {emit("utf8","Q",b);emit("utf8","P",append(append([]byte{'"'},b...), '"'))}
 for _,s:=range []string{"0","-0","1","-1","9007199254740993","18446744073709551615","18446744073709551616","9223372036854775807","9223372036854775808","-9223372036854775808","-9223372036854775809","","00","01","-01","+1","1e0","1.0"," 1","1 ","--1",strings.Repeat("9",65536)} {emit("integer","U",[]byte(s));emit("integer","I",[]byte(s))}
 for _,n:=range []int{31,32,33}{emit("depth-bound","P",[]byte(strings.Repeat("[",n)+"0"+strings.Repeat("]",n)))}
 for _,n:=range []int{4093,4094,4095}{emit("token-bound","P",[]byte("["+strings.Repeat("0,",n-1)+"0]"))}
 for _,n:=range []int{255,256,257}{
  fields:=make([]string,n);for i:=range fields{fields[i]=fmt.Sprintf(`"key%03d":0`,i)}
  obj:="{"+strings.Join(fields,",")+"}"
  emit("member-bound","P",[]byte(obj))
  emit("nested-member-bound","P",[]byte(`{"nested":`+obj+`}`))
 }
 fields:=make([]string,256);for i:=range fields{fields[i]=fmt.Sprintf(`"%s%03x":0`,strings.Repeat("a",247),i)}
 worst:="{"+strings.Join(fields,",")+"}"
 worst+=strings.Repeat(" ",65536-len(worst))
 emit("member-long-prefix","P",[]byte(worst))
 for _,n:=range []int{65533,65534}{emit("message-bound","P",[]byte(`"`+strings.Repeat("a",n)+`"`))}
 emit("message-bound","P",[]byte(strings.Repeat(" ",65535)+"0"))
 emit("message-bound","P",[]byte(strings.Repeat(" ",65536)))
 for _,n:=range []int{21845,21846}{emit("decoded-bound","P",append(append([]byte{'"'},bytes.Repeat([]byte{255},n)...),'"'))}
 emit("writer-bound","Q",bytes.Repeat([]byte{0},65536))
 emit("writer-bound","P",[]byte(`"`+strings.Repeat("<",12000)+`"`))
 r:=rand.New(rand.NewPCG(1020,2119))
 for range 2000 {
  b,e:=json.Marshal(randomValue(r,0));if e!=nil{panic(e)};emit("random-valid","P",b)
  if len(b)>0{c:=append([]byte(nil),b...);c[r.IntN(len(c))]=byte(r.IntN(256));emit("random-mutation","P",c)}
 }
 for range 1000{b:=randomBytes(r,r.IntN(100));emit("random-bytes","P",b);emit("random-quote","Q",b)}
 for range 500{v:=r.Uint64();emit("random-integer","U",[]byte(strconv.FormatUint(v,10)));emit("random-integer","I",[]byte(strconv.FormatInt(int64(v),10)))}
}
