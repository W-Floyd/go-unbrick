package vendor

import (
	"strings"
	"testing"
)

func TestHKMCManifests(t *testing.T) {
	files := map[string][]byte{
		"c.ver":       []byte("+|1|B|kia|COLL|1|0\nCOLL|a.bin|1|-5|10|0\n"),
		"update.info": []byte("./modem\n: m.bin:" + strings.Repeat("ab", 28) + "\n"),
	}
	pkg := PackageAccess{Names: map[string]bool{}, Read: func(n string) []byte { return files[n] }}
	for n := range files {
		pkg.Names[n] = true
	}
	got := map[string]FileClaim{}
	for _, c := range (hkmc{}).Manifests(pkg) {
		got[c.Path] = c
	}
	if c := got["a.bin"]; c.Algo != "crc32" || c.Size != 10 || c.Sum != "fffffffb" {
		t.Errorf("ver claim: %+v", c)
	}
	if c := got["modem/m.bin"]; c.Algo != "hyundai-sha224" || len(c.Sum) != 56 {
		t.Errorf("update.info claim: %+v", c)
	}
}
