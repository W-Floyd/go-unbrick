package vendor

import (
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/lenovo"
)

func TestLMSAOutName(t *testing.T) {
	for in, want := range map[string]string{
		"MT6765_Android_scatter.t": "MT6765_Android_scatter.txt",
		"rawprogram0.x":            "rawprogram0.xml",
		"SCATTER.T":                "SCATTER.Txt", // extension matched case-insensitively
		"flash_tool.exe":           "",
		"scatter.txt":              "",
	} {
		if got := lmsaOutName(in); got != want {
			t.Errorf("lmsaOutName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLMSAExpander(t *testing.T) {
	const pw = "captured-session-key"
	enc, err := lenovo.EncryptROM([]byte("<?xml version=\"1.0\"?><data/>"), pw)
	if err != nil {
		t.Fatal(err)
	}
	// The recovered default decrypts a real package with no env set.
	def, err := lenovo.EncryptROM([]byte("ok"), lenovo.DefaultPassword)
	if err != nil {
		t.Fatal(err)
	}
	if kids, err := expandLMSAROM(carve.FromBytes("version.t", def)); err != nil {
		t.Fatalf("default-password expand: %v", err)
	} else if len(kids) != 1 || kids[0].Name != "version.txt" {
		t.Fatalf("default-password children = %v", kids)
	}

	// LMSAPasswordEnv overrides the recovered default for a non-default package.
	node := carve.FromBytes("rawprogram0.x", enc)
	t.Setenv(LMSAPasswordEnv, pw)
	kids, err := expandLMSAROM(node)
	if err != nil {
		t.Fatal(err)
	}
	if len(kids) != 1 || kids[0].Name != "rawprogram0.xml" {
		t.Fatalf("expander children = %v", kids)
	}
	got, err := kids[0].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "<?xml version=\"1.0\"?><data/>" {
		t.Fatalf("decrypted child = %q", got)
	}
}
