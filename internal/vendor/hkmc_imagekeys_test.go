package vendor

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/facts"
)

func TestLearnImageDat(t *testing.T) {
	files := map[string][]byte{
		"enc_system/enc_system.ext4/system.ext4/etc/iv.dat":    {0xde, 0xad, 0xbe, 0xef},
		"enc_system/enc_system.ext4/system.ext4/etc/image.dat": []byte("0011223344556677\n"),
	}
	pkg := PackageAccess{
		Names:    map[string]bool{"enc_system/enc_system.ext4": true},
		Read:     func(n string) []byte { return files[n] },
		Decrypts: func() bool { return true },
	}
	bag := facts.NewBag()
	learnImageDat(pkg, bag)
	if v, _ := facts.Get(bag, ImageIV); !strings.HasPrefix(v, "deadbeef (4 bytes)") {
		t.Errorf("iv = %q", v)
	}
	if v, _ := facts.Get(bag, ImageKey); !strings.HasPrefix(v, "0011223344556677 (17 bytes, text)") {
		t.Errorf("key = %q", v)
	}
	pkg.Decrypts = func() bool { return false }
	bag = facts.NewBag()
	learnImageDat(pkg, bag)
	if bag.Has("image_iv") {
		t.Error("read without keys")
	}
}
