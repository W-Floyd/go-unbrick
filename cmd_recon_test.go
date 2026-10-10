package main

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/facts"
)

func TestServregNote(t *testing.T) {
	const adspua = `{"sr_version":{"major":1,"minor":1,"patch":1},
	"sr_domain":{"soc":"msm","domain":"adsp","subdomain":"audio_pd","qmi_instance_id":74},
	"sr_service":[{"provider":"tms","service":"servreg"},{"provider":"avs","service":"audio"}]}`
	if got, want := servregNote([]byte(adspua)), "service registry: adsp/audio_pd provides tms/servreg, avs/audio"; got != want {
		t.Errorf("servregNote = %q, want %q", got, want)
	}
	if got := servregNote([]byte(`{"other":1}`)); got != "" {
		t.Errorf("non-servreg JSON: %q", got)
	}
}

func TestWithinRefusesEscape(t *testing.T) {
	for name, ok := range map[string]bool{
		"image/adsp.mdt":   true,
		"/abs/path":        true, // made relative
		"../../etc/passwd": false,
		"a/../../b":        false,
	} {
		if _, err := within("out", name); (err == nil) != ok {
			t.Errorf("within(%q): err %v", name, err)
		}
	}
}

func TestBuildTreeDir(t *testing.T) {
	a := carve.FromBytes("image/adsp.mdt", nil)
	b := carve.FromBytes("image/sub/x.bin", nil)
	c := carve.FromBytes("top.txt", nil)
	d := buildTreeDir([]*carve.Node{a, b, c})
	img := d.dirs["image"]
	if len(d.files) != 1 || d.base[c] != "top.txt" || img == nil || img.base[a] != "adsp.mdt" ||
		img.dirs["sub"] == nil || img.dirs["sub"].base[b] != "x.bin" {
		t.Fatalf("tree: %+v", d)
	}
}

func TestLoaderLines(t *testing.T) {
	v.Set("catalog", "catalog")
	v.Set("library", t.TempDir())
	bag := func(oem, root string) *facts.Bag {
		b := facts.NewBag()
		p := facts.Provenance{Source: "test", Authority: facts.Attested}
		facts.Set(b, facts.OEMID, oem, p)
		facts.Set(b, facts.RootKeyHash, root, p)
		facts.Set(b, facts.SoC, "Qualcomm SM6225 Snapdragon 680", p)
		return b
	}
	// fogona's root signs a loader the index holds for its SM6225.
	got := loaderLines(bag("02E8", "8b2d1c830d9d85768b0e192d66f5bf307a390691b32f8bd2571943a8a8e34a8a"))
	if len(got) < 2 || !strings.Contains(strings.Join(got, "\n"), "001b80e102e80000_8b2d1c830d9d8576_fhprg_moto_g52.bin") {
		t.Errorf("fogona: %q", got)
	}
	// a05s: Samsung's root, no loader known.
	got = loaderLines(bag("0020", "3bafc69540869a32b0448ab38484c130a6ba5e08822cda0d24002aa01e6a7ae3"))
	if len(got) != 1 || !strings.HasPrefix(got[0], "Loader: none known for 001B80E1") {
		t.Errorf("a05s: %q", got)
	}
}

func TestProductKey(t *testing.T) {
	p := facts.Provenance{Source: "test", Authority: facts.Attested}
	bag := func(fp, model string) *facts.Bag {
		b := facts.NewBag()
		facts.Set(b, facts.BuildFingerprint, fp, p)
		if model != "" {
			facts.Set(b, facts.Model, model, p)
		}
		return b
	}
	for _, c := range []struct {
		fp, model, want string
		ok              bool
	}{
		{"samsung/a05sddxx/a05s:13/TP1A/M145FXXSDDZH1:user/release-keys", "", "a05s", true},
		{"qti/bengal_515/bengal_515:13/TKQ1/eng:user/dev-keys", "FiiO M21", "bengal_515-fiio-m21", true},
		{"qti/bengal_515/bengal_515:13/TKQ1/eng:user/dev-keys", "", "", false},
	} {
		codename := "a05s"
		if c.want != "a05s" {
			codename = "bengal_515"
		}
		if got, ok := productKey(bag(c.fp, c.model), codename); got != c.want || ok != c.ok {
			t.Errorf("%s %q: %q %v, want %q %v", c.fp, c.model, got, ok, c.want, c.ok)
		}
	}
}
