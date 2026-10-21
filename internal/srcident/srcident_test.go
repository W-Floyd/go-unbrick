package srcident

import (
	"strings"
	"testing"
)

var testRules = []Rule{
	{ID: "u-boot", Names: []string{"uboot"}, Repo: "https://example.test/u-boot.git", Tag: "v{version}",
		Version: []VersionSource{{File: "Makefile", Pattern: `(?s)VERSION\s*=\s*(\d+).*?PATCHLEVEL\s*=\s*(\d+)`, Format: "{1}.{2}"}}},
	{ID: "openssl", Repo: "https://example.test/openssl.git", Tag: "OpenSSL_{version_}",
		Version: []VersionSource{{File: "openssl.version", Pattern: `OPENSSL_VERSION=(\S+)`}}},
	{ID: "gstreamer", Repo: "https://example.test/gst.git"},
	{ID: "kenlm", Names: []string{"kenlm-src"}, Repo: "https://example.test/kenlm.git"},
	{ID: "e2fsprogs", AOSP: "external/e2fsprogs", Repo: "https://example.test/e2fs.git", Tag: "v{version}"},
}

func names(prefix string, files ...string) []string {
	var out []string
	for _, f := range files {
		out = append(out, prefix+f)
	}
	return out
}

func TestFind(t *testing.T) {
	var all []string
	all = append(all, names("0109_X_kernel.lk/2/u-boot/", "Makefile", "README", "common/a.c")...)
	all = append(all, names("0109_X_kernel.lk/2/lib/openssl/", "openssl.version", "e_os.h", "x.c")...)
	all = append(all, names("ccNC_gstreamer/gstreamer-1.16.3_r0/gstreamer-1.16.3/", "a.c", "b.c", "c.c")...)
	all = append(all, names("ccNC_42dot/kenlm-src/", "lm/a.cc", "lm/b.cc", "util/bit_packing.hh")...)
	all = append(all, names("0068_X_platform.external.e2fsprogs/2/", "lib/a.c", "lib/b.c", "misc/c.c")...)
	all = append(all, "ccNC_42dot_kenlm_notice.txt", "other.txt")
	files := map[string]string{
		"0109_X_kernel.lk/2/u-boot/Makefile":             "VERSION = 2016\nPATCHLEVEL = 01\nSUBLEVEL =\n",
		"0109_X_kernel.lk/2/lib/openssl/openssl.version": "OPENSSL_VERSION=1.0.0a\n",
		"ccNC_42dot_kenlm_notice.txt":                    "/* File Path 1: util/bit_packing.hh via kenlm_5bf7b46.patch */\n",
	}
	read := func(n string) []byte {
		if s, ok := files[n]; ok {
			return []byte(s)
		}
		return nil
	}
	got := map[string]Candidate{}
	for _, c := range Find(all, read, testRules) {
		got[c.Rule.ID] = c
	}
	check := func(id, root, version, ref string) {
		t.Helper()
		c, ok := got[id]
		if !ok {
			t.Errorf("%s: not found", id)
			return
		}
		if c.Root != root || c.Version != version || c.Ref != ref {
			t.Errorf("%s: root %q version %q ref %q; want %q %q %q", id, c.Root, c.Version, c.Ref, root, version, ref)
		}
	}
	check("u-boot", "0109_X_kernel.lk/2/u-boot", "2016.01", "v2016.01")
	check("openssl", "0109_X_kernel.lk/2/lib/openssl", "1.0.0a", "OpenSSL_1_0_0a")
	check("gstreamer", "ccNC_gstreamer/gstreamer-1.16.3_r0/gstreamer-1.16.3", "1.16.3", "1.16.3")
	check("kenlm", "ccNC_42dot/kenlm-src", "", "5bf7b46")
	check("e2fsprogs", "0068_X_platform.external.e2fsprogs/2", "", "")
	if c := got["kenlm"]; !strings.Contains(c.Evidence, "pinned by notice") {
		t.Errorf("evidence %q", c.Evidence)
	}
}

func TestTagFor(t *testing.T) {
	r := Rule{Tag: "OpenSSL_{version_}"}
	if r.TagFor("1.0.1e") != "OpenSSL_1_0_1e" || r.TagFor("") != "" {
		t.Error("tag template")
	}
	if (&Rule{}).TagFor("3.1.7") != "3.1.7" {
		t.Error("default tag")
	}
}

func TestSplitName(t *testing.T) {
	for in, want := range map[string][2]string{
		"gstreamer-1.16.3_r0": {"gstreamer", "1.16.3"}, "vsomeip-3.1.7-r2": {"vsomeip", "3.1.7"},
		"u-boot": {"u-boot", ""}, "openssl_1.0.1e": {"openssl", "1.0.1e"}, "gst-plugins-bad-1.16.3_r0": {"gst-plugins-bad", "1.16.3"},
	} {
		if s, v := splitName(in); s != want[0] || v != want[1] {
			t.Errorf("%s: %q %q", in, s, v)
		}
	}
}

func TestStrictAndNesting(t *testing.T) {
	rules := []Rule{
		{ID: "linux", Names: []string{"linux"}, Repo: "r", Strict: true},
		{ID: "u-boot", Repo: "r2"},
	}
	var all []string
	all = append(all, names("t/u-boot/include/linux/", "a.h", "b.h", "c.h")...)
	all = append(all, names("t/u-boot/", "x.c", "y.c", "z.c")...)
	all = append(all, names("t/other/linux/", "a.c", "b.c", "c.c")...)
	all = append(all, names("t/linux-4.9/", "a.c", "b.c", "c.c")...)
	var got []string
	for _, c := range Find(all, func(string) []byte { return nil }, rules) {
		got = append(got, c.Rule.ID+" "+c.Root+" "+c.Version)
	}
	want := "linux t/linux-4.9 4.9 | u-boot t/u-boot "
	if s := strings.Join(got, " | "); s != want {
		t.Errorf("got %q want %q", s, want)
	}
}

func TestTagVersion(t *testing.T) {
	r := &Rule{Tag: "v{version}"}
	for tag, want := range map[string]string{"v1.42.9": "1.42.9", "v1.43-rc1": "", "e2fsprogs-1.42.9": "", "v1.0.1e": "1.0.1e"} {
		if v, ok := r.TagVersion(tag); v != want || ok != (want != "") {
			t.Errorf("%s: %q %v", tag, v, ok)
		}
	}
	o := &Rule{Tag: "OpenSSL_{version_}"}
	if v, ok := o.TagVersion("OpenSSL_1_0_0a"); !ok || v != "1.0.0a" {
		t.Errorf("openssl tag: %q %v", v, ok)
	}
	if v, ok := (&Rule{}).TagVersion("3.1.7"); !ok || v != "3.1.7" {
		t.Errorf("default tag: %q %v", v, ok)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.9", "1.10", -1}, {"1.42.9", "1.42.9", 0}, {"2.0", "1.99.9", 1}, {"1.0.1e", "1.0.1d", 1}, {"1.0", "1.0.1", -1}, {"1.0.1", "1.0.1a", -1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s: %d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestOSVRepo(t *testing.T) {
	if (&Rule{Repo: "a"}).OSVRepo() != "a" || (&Rule{Repo: "a", OSV: "b"}).OSVRepo() != "b" {
		t.Error("osv repo")
	}
}
