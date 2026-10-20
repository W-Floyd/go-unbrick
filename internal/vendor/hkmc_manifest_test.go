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

// A .ver row's column 0 carries the file's sub-directory after the collection, so
// a claim for a nested file is under it: without it no claim matches the file.
func TestVerClaimsKeepTheSubDirectory(t *testing.T) {
	ver := "+|1|B|kia|2019_21_G70_CAN|2|0\n" +
		"2019_21_G70_CAN\\DAUDIOPLUS\\can\\ik\\update|f.bin|1|-5|10|0\n" +
		"2019_21_G70_CAN|top.bin|2|7|20|0\n"
	m := ParseVer([]byte(ver))
	if len(m.Entries) != 2 || m.Entries[0].Dir != "DAUDIOPLUS/can/ik/update" || m.Entries[1].Dir != "" {
		t.Fatalf("%+v", m.Entries)
	}
	files := map[string][]byte{"pkg/c.ver": []byte(ver)}
	pkg := PackageAccess{Names: map[string]bool{"pkg/c.ver": true}, Read: func(n string) []byte { return files[n] }}
	got := map[string]bool{}
	for _, c := range (hkmc{}).Manifests(pkg) {
		got[c.Path] = true
	}
	if !got["pkg/DAUDIOPLUS/can/ik/update/f.bin"] || !got["pkg/top.bin"] {
		t.Errorf("claim paths: %v", got)
	}
	// With no header row the collection is what precedes the first backslash.
	if m := ParseVer([]byte("COLL\\a\\b|x.bin|1|1|1|0\n")); len(m.Entries) != 1 || m.Entries[0].Dir != "a/b" {
		t.Errorf("no header: %+v", m.Entries)
	}
}
