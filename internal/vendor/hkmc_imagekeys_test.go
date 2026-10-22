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

func TestKeyFilePatternsNameTheDatFiles(t *testing.T) {
	var match func(string) bool = func(p string) bool {
		for _, re := range KeyFilePatterns() {
			if re.MatchString(p) {
				return true
			}
		}
		return false
	}
	for _, p := range []string{"iv.dat", "enc_system/enc_system.ext4/system.ext4/etc/image.dat", "x.tar/res/iv.dat"} {
		if !match(p) {
			t.Errorf("%s is a key file", p)
		}
	}
	for _, p := range []string{"notiv.dat", "image.dat.bak", "etc/iv.data"} {
		if match(p) {
			t.Errorf("%s is not", p)
		}
	}
}
