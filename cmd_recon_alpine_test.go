package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

// fjhdmiKids builds the three-member node set printFjhdmiReport/
// verifyFjhdmiManifest expect, with fbdmisha512 computed from the actual
// bytes given (so a test can flip one byte afterwards to produce a real
// mismatch instead of a hand-typed wrong hash).
func fjhdmiKids(t *testing.T, iniBody, zipBody []byte) []*carve.Node {
	t.Helper()
	hashOf := func(b []byte) string {
		sum := sha512.Sum512(b)
		return hex.EncodeToString(sum[:])
	}
	manifest := []byte(hashOf(iniBody) + " *./update.ini\n" + hashOf(zipBody) + " *./update.zip\n")
	return []*carve.Node{
		carve.FromBytes("fbdmisha512", manifest),
		carve.FromBytes("update.ini", iniBody),
		carve.FromBytes("update.zip", zipBody),
	}
}

func captureRecon(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestPrintFjhdmiReport(t *testing.T) {
	ini := []byte("#MODEL_TYPE = FBDMI\n#UPDATE_VERSION = FBDMI_1.3.13_2022.03.08\n#SYSTEM_UPDATE = 1\n#MICOM_UPDATE = 1\n")
	kids := fjhdmiKids(t, ini, []byte("PK\x03\x04payload"))

	out := captureRecon(t, func() {
		if !printFjhdmiReport(kids, "  ") {
			t.Fatal("printFjhdmiReport returned false for a recognised container")
		}
	})
	for _, want := range []string{"Model:          FBDMI", "Update version: FBDMI_1.3.13_2022.03.08", "System update:  yes, MICOM update: yes"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Fatalf("output missing %q, got:\n%s", want, out)
		}
	}
	if bytes.Contains([]byte(out), []byte("verified")) {
		t.Fatalf("hash verification ran without --verify, got:\n%s", out)
	}
}

func TestPrintFjhdmiReportNotThisContainer(t *testing.T) {
	kids := []*carve.Node{carve.FromBytes("boot.img", []byte("not fjhdmi"))}
	if printFjhdmiReport(kids, "  ") {
		t.Fatal("printFjhdmiReport should return false: no update.ini among kids")
	}
}

func TestVerifyFjhdmiManifestOK(t *testing.T) {
	old := reconVerify
	reconVerify = true
	defer func() { reconVerify = old }()

	ini := []byte("#MODEL_TYPE = FBDMI\n")
	kids := fjhdmiKids(t, ini, []byte("PK\x03\x04payload"))
	out := captureRecon(t, func() { printFjhdmiReport(kids, "  ") })
	if !bytes.Contains([]byte(out), []byte("fbdmisha512: 2 file(s) verified")) {
		t.Fatalf("expected both files verified, got:\n%s", out)
	}
	if bytes.Contains([]byte(out), []byte("mismatch")) {
		t.Fatalf("unexpected mismatch reported:\n%s", out)
	}
}

func TestVerifyFjhdmiManifestMismatch(t *testing.T) {
	old := reconVerify
	reconVerify = true
	defer func() { reconVerify = old }()

	ini := []byte("#MODEL_TYPE = FBDMI\n")
	zip := []byte("PK\x03\x04payload")
	kids := fjhdmiKids(t, ini, zip)
	// Corrupt update.zip's bytes after the manifest was built from the
	// original, so its hash no longer matches what fbdmisha512 says.
	for i, k := range kids {
		if filepath.Base(k.Name) == "update.zip" {
			kids[i] = carve.FromBytes("update.zip", append(append([]byte(nil), zip...), 'X'))
		}
	}
	out := captureRecon(t, func() { printFjhdmiReport(kids, "  ") })
	if !bytes.Contains([]byte(out), []byte("hash mismatch: update.zip")) {
		t.Fatalf("expected a reported mismatch for update.zip, got:\n%s", out)
	}
}
