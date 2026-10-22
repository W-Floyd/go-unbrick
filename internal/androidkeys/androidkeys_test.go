package androidkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// format writes pub as dumpkey does: words as signed 32-bit values when signed.
func format(pub *rsa.PublicKey, signed bool) string {
	words := (pub.N.BitLen() + 31) / 32
	two32 := new(big.Int).Lsh(big.NewInt(1), 32)
	inv := new(big.Int).ModInverse(new(big.Int).Mod(pub.N, two32), two32)
	n0inv := new(big.Int).Sub(two32, inv).Uint64()
	rr := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(64*words)), pub.N)
	list := func(x *big.Int) string {
		var s []string
		mask := big.NewInt(0xffffffff)
		for i := 0; i < words; i++ {
			w := new(big.Int).And(new(big.Int).Rsh(x, uint(32*i)), mask).Int64()
			if signed {
				w = int64(int32(w))
			}
			s = append(s, fmt.Sprint(w))
		}
		return strings.Join(s, ",")
	}
	out := fmt.Sprintf("{%d,0x%08x,{%s},{%s}}", words, n0inv, list(pub.N), list(rr))
	if pub.E != 65537 {
		out += fmt.Sprintf(",%d", pub.E)
	}
	return out
}

func TestParseRoundTrip(t *testing.T) {
	k1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, signed := range []bool{false, true} {
		data := []byte(format(&k1.PublicKey, signed) + ",\n" + format(&k2.PublicKey, signed) + "\n")
		keys, ok := Parse(data)
		if !ok || len(keys) != 2 {
			t.Fatalf("signed=%v: %d keys, ok=%v", signed, len(keys), ok)
		}
		for i, want := range []*rsa.PublicKey{&k1.PublicKey, &k2.PublicKey} {
			if keys[i].Public.N.Cmp(want.N) != 0 || keys[i].Public.E != 65537 || !keys[i].Consistent {
				t.Errorf("signed=%v key %d: %+v", signed, i, keys[i])
			}
		}
		if keys[0].Bits != 2048 || keys[1].Bits != 1024 {
			t.Errorf("bits %d, %d", keys[0].Bits, keys[1].Bits)
		}
	}
}

func TestParseExponentAndTamper(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pub := &rsa.PublicKey{N: k.N, E: 3}
	keys, ok := Parse([]byte(format(pub, false)))
	if !ok || keys[0].Public.E != 3 {
		t.Fatalf("exponent: %+v ok=%v", keys, ok)
	}
	// A changed n0inv is still a key, but flagged.
	good := format(&k.PublicKey, false)
	i := strings.Index(good, ",0x") + 3
	bad := good[:i] + "00000001" + good[i+8:]
	keys, ok = Parse([]byte(bad))
	if !ok || keys[0].Consistent {
		t.Errorf("a wrong n0inv: ok=%v keys=%+v", ok, keys)
	}
}

func TestParseRefusesOtherText(t *testing.T) {
	for _, s := range []string{
		"", "hello\n", "{ \"json\": 1 }", "{64,0x1,{1},{1}", "{2,0xdeadbeef,{1,2},{1}}",
		"/* {64,0xea07899b,{1,2},{3,4}} not at the start */",
	} {
		if keys, ok := Parse([]byte(s)); ok {
			t.Errorf("%q parsed as %d keys", s, len(keys))
		}
	}
	if Is([]byte("plain text")) {
		t.Error("plain text is not res/keys")
	}
}
