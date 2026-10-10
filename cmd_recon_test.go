package main

import (
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/carve"
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
