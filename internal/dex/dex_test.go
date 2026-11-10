package dex

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// testdata/probe.dex is testdata/Probe.java built by
//
//	javac --release 11 -d classes Probe.java
//	d8 --min-api 26 --output . classes/com/example/*.class
func TestListings(t *testing.T) {
	b, err := os.ReadFile("testdata/probe.dex")
	if err != nil {
		t.Fatal(err)
	}
	classes, err := Classes(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	strs, err := Strings(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ got, want string }{
		{classes, "public final class com.example.Probe implements java.lang.Runnable  // Probe.java\n"},
		{classes, "  public static final java.lang.String URL\n"},
		{classes, "  private transient int[][] grid\n"},
		{classes, "  public <init>(int)\n"},
		{classes, "  protected static synchronized long sum(java.lang.String[], double)\n"},
		{classes, "public interface com.example.Probe$Listener  // Probe.java\n  public abstract void on(com.example.Probe)\n"},
		{classes, "final enum com.example.Probe$Mode extends java.lang.Enum"},
		{strs, `"https://probe.example/v1\n"` + "\n"},
	} {
		if !strings.Contains(c.got, c.want) {
			t.Errorf("missing %q in\n%s", c.want, c.got)
		}
	}
}

// carve hands these whatever a container holds: a damaged DEX must error,
// never panic.
func TestMalformed(t *testing.T) {
	b, err := os.ReadFile("testdata/probe.dex")
	if err != nil {
		t.Fatal(err)
	}
	for i := range b {
		for _, in := range [][]byte{b[:i], func() []byte { c := bytes.Clone(b); c[i] ^= 0xff; return c }()} {
			Classes(bytes.NewReader(in), int64(len(in)))
			Strings(bytes.NewReader(in), int64(len(in)))
		}
	}
}
