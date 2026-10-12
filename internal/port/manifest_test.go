package port

import (
	"strings"
	"testing"
)

func TestManifestCountsOpenDecisions(t *testing.T) {
	files := map[string][]byte{
		"a/deviceinfo": []byte("# Draft. Lines marked TODO need a decision.\n# TODO: year: not recorded\nname=\"x\"\n# TODO: dtb: pick one\n"),
		"b.dts":        []byte("/* TODO: chassis */\nmodel = \"x\";\n"),
		"clean.json":   []byte("{}"),
		"blob.bin":     {0, 1, 2, 'T', 'O', 'D', 'O'},
	}
	out := Manifest(files)
	for _, want := range []string{
		"| a/deviceinfo | ", "| 2 |", // the explaining header is not a decision
		"| b.dts | ", "| 1 |",
		"| clean.json | 2 B | 0 |",
		"| blob.bin | 7 B | — |",
		"3 open decisions in all.",
		"`a/deviceinfo`: TODO: year: not recorded",
		"`b.dts`: TODO: chassis",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Lines marked TODO need") {
		t.Errorf("the explanatory header leaked into the list:\n%s", out)
	}
}
