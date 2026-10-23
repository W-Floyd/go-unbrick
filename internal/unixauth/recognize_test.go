package unixauth

import (
	"testing"

	"github.com/W-Floyd/go-unbrick/pkg/analysis/recognize"
)

var _ recognize.Recognizer = Recognizer{}

func TestRecognizer(t *testing.T) {
	data := []byte("root:TOG3DLSQdFPY.:19290:0:99999:7:::\ndaemon:*:19290:0:99999:7:::\n")

	r := Recognizer{}
	if !r.Claims("shadow", data) {
		t.Fatal("should claim a file named shadow")
	}
	if r.Claims("not-shadow", data) {
		t.Error("should not claim an arbitrary name")
	}
	if got := r.Label("shadow", data); got != "shadow file" {
		t.Errorf("label %q", got)
	}
	if s := r.Summary("shadow", data, nil); s != "" {
		t.Errorf("summary should be empty (the label already names it), got %q", s)
	}
	lines := r.Report("/etc/shadow", "shadow", data, nil)
	if len(lines) == 0 || lines[0] != "1 of 2 account(s) have a password: des-crypt (weak)" {
		t.Errorf("report %+v", lines)
	}
}

func TestRecognizerPasswd(t *testing.T) {
	data := []byte("root:x:0:0:root:/root:/bin/sh\n")
	r := Recognizer{}
	if got := r.Label("passwd", data); got != "passwd file" {
		t.Errorf("label %q", got)
	}
	lines := r.Report("/etc/passwd", "passwd", data, nil)
	if len(lines) != 1 || lines[0] != "1 account(s)" {
		t.Errorf("report %+v", lines)
	}
}
