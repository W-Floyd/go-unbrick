package hashcache

import (
	"path/filepath"
	"testing"
)

func fresh(t *testing.T) {
	Path = filepath.Join(t.TempDir(), "h.jsonl")
	t.Cleanup(func() { Path = ""; Reset() })
	Reset()
}

func TestPersistsAcrossLoads(t *testing.T) {
	fresh(t)
	if _, ok := Get("k", 3, false); ok {
		t.Fatal("hit on an empty store")
	}
	Put("k", 3, "abc", false)
	Put("k", 3, "abc", false) // no duplicate record
	Reset()                   // a new process
	if s, ok := Get("k", 3, false); !ok || s != "abc" {
		t.Fatalf("got %q %v", s, ok)
	}
	if _, ok := Get("k", 4, false); ok {
		t.Fatal("hit for a different size")
	}
	if _, ok := Get("", 3, false); ok {
		t.Fatal("hit for an empty key")
	}
	Put("k", 3, "def", false) // last wins
	Reset()
	if s, _ := Get("k", -1, false); s != "def" {
		t.Fatalf("got %q", s)
	}
}

func TestClaimsAreOnlyTrustedOnRequest(t *testing.T) {
	fresh(t)
	Put("m", 5, "claimed", true)
	if _, ok := Get("m", 5, false); ok {
		t.Fatal("a manifest's claim served to a verifying lookup")
	}
	if s, ok := Get("m", 5, true); !ok || s != "claimed" {
		t.Fatalf("got %q %v", s, ok)
	}
	Put("m", 5, "computed", false) // a computed hash replaces the claim...
	Put("m", 5, "claimed", true)   // ...and a later claim does not displace it
	Reset()
	if s, ok := Get("m", 5, false); !ok || s != "computed" {
		t.Fatalf("got %q %v", s, ok)
	}
}
