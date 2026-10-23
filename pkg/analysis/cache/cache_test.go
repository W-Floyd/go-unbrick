package cache

import (
	"path/filepath"
	"testing"
)

// withVersions runs fn with Versions temporarily set to vs, restoring the real
// registry after -- tests must not permanently mutate the package-level
// registry other tests (and other packages in the same binary) read.
func withVersions(t *testing.T, vs map[string]int, fn func()) {
	t.Helper()
	old := Versions
	Versions = vs
	t.Cleanup(func() { Versions = old })
	fn()
}

func TestDomainVersionChangesOnlyWithItsMembers(t *testing.T) {
	withVersions(t, map[string]int{"a": 1, "b": 1, "c": 1}, func() {
		d := Domain{"d", []string{"a", "b"}}
		v1 := d.Version()
		Versions["c"] = 2 // not a member of d
		if d.Version() != v1 {
			t.Error("a non-member's version changing should not change d's")
		}
		Versions["a"] = 2 // a member
		if d.Version() == v1 {
			t.Error("a member's version changing should change d's")
		}
	})
}

func TestDomainVersionIsOrderIndependent(t *testing.T) {
	withVersions(t, map[string]int{"a": 3, "b": 5}, func() {
		d1 := Domain{"d", []string{"a", "b"}}
		d2 := Domain{"d", []string{"b", "a"}}
		if d1.Version() != d2.Version() {
			t.Error("member order should not affect the version")
		}
	})
}

func TestStoreGetPutRoundTrip(t *testing.T) {
	withVersions(t, map[string]int{"a": 1}, func() {
		s := Open(filepath.Join(t.TempDir(), "c.jsonl"))
		d := Domain{"d", []string{"a"}}
		if _, ok := s.Get(d, "k"); ok {
			t.Fatal("a cold cache should miss")
		}
		s.Put(d, "k", "hello")
		if text, ok := s.Get(d, "k"); !ok || text != "hello" {
			t.Errorf("got %q, %v", text, ok)
		}
	})
}

func TestStoreMissesOnVersionBump(t *testing.T) {
	withVersions(t, map[string]int{"a": 1}, func() {
		s := Open(filepath.Join(t.TempDir(), "c.jsonl"))
		d := Domain{"d", []string{"a"}}
		s.Put(d, "k", "hello")
		Versions["a"] = 2 // simulate learning to parse "a" better
		if _, ok := s.Get(d, "k"); ok {
			t.Error("a stale entry (by domain version) should miss, not be returned")
		}
	})
}

func TestStoreMissesOnDomainMismatch(t *testing.T) {
	withVersions(t, map[string]int{"a": 1}, func() {
		s := Open(filepath.Join(t.TempDir(), "c.jsonl"))
		d1 := Domain{"one", []string{"a"}}
		d2 := Domain{"two", []string{"a"}}
		s.Put(d1, "k", "hello")
		if _, ok := s.Get(d2, "k"); ok {
			t.Error("the same key under a different domain should miss")
		}
	})
}

func TestStorePersistsAcrossInstances(t *testing.T) {
	withVersions(t, map[string]int{"a": 1}, func() {
		p := filepath.Join(t.TempDir(), "c.jsonl")
		d := Domain{"d", []string{"a"}}
		Open(p).Put(d, "k", "hello")

		s2 := Open(p)
		if text, ok := s2.Get(d, "k"); !ok || text != "hello" {
			t.Errorf("got %q, %v", text, ok)
		}
	})
}

func TestStoreLastWriteWinsOnReload(t *testing.T) {
	withVersions(t, map[string]int{"a": 1}, func() {
		p := filepath.Join(t.TempDir(), "c.jsonl")
		d := Domain{"d", []string{"a"}}
		Open(p).Put(d, "k", "first")
		Open(p).Put(d, "k", "second")

		if text, ok := Open(p).Get(d, "k"); !ok || text != "second" {
			t.Errorf("got %q, %v", text, ok)
		}
	})
}

func TestStoreMissingOrDamagedFileIsJustEmpty(t *testing.T) {
	withVersions(t, map[string]int{"a": 1}, func() {
		d := Domain{"d", []string{"a"}}
		if _, ok := Open(filepath.Join(t.TempDir(), "nonexistent.jsonl")).Get(d, "k"); ok {
			t.Error("a missing file should miss, not error or panic")
		}
	})
}

func TestStoreEmptyKeyNeverStored(t *testing.T) {
	withVersions(t, map[string]int{"a": 1}, func() {
		s := Open(filepath.Join(t.TempDir(), "c.jsonl"))
		d := Domain{"d", []string{"a"}}
		s.Put(d, "", "text")
		if _, ok := s.Get(d, ""); ok {
			t.Error("an empty key should never be stored or found")
		}
	})
}

func TestInMemoryStoreNeedsNoPath(t *testing.T) {
	withVersions(t, map[string]int{"a": 1}, func() {
		s := Open("")
		d := Domain{"d", []string{"a"}}
		s.Put(d, "k", "hello")
		if text, ok := s.Get(d, "k"); !ok || text != "hello" {
			t.Errorf("got %q, %v", text, ok)
		}
	})
}

func TestDefaultGetPut(t *testing.T) {
	withVersions(t, map[string]int{"a": 1}, func() {
		old := DefaultPath
		DefaultPath = filepath.Join(t.TempDir(), "default.jsonl")
		t.Cleanup(func() { DefaultPath = old })
		Default = Open("") // force a fresh, unloaded instance under the new path for this test

		d := Domain{"d", []string{"a"}}
		Put(d, "k", "hello")
		if text, ok := Get(d, "k"); !ok || text != "hello" {
			t.Errorf("got %q, %v", text, ok)
		}
	})
}

// A real cascading-invalidation scenario, matching the package doc's claim: a
// container's listing and its member's listing share a Domain (as Listing
// does for npkg), so bumping npkg invalidates both without anything tracking
// that the member sits inside the container.
func TestCascadingInvalidationThroughASharedDomain(t *testing.T) {
	withVersions(t, map[string]int{"carve-containers": 1, "npkg": 1}, func() {
		s := Open(filepath.Join(t.TempDir(), "c.jsonl"))
		listing := Domain{"listing", []string{"carve-containers", "npkg"}}
		s.Put(listing, "container-key", "container listing text")
		s.Put(listing, "member-key", "member listing text")

		Versions["npkg"] = 2 // "we learn more about a format and parse better"

		if _, ok := s.Get(listing, "container-key"); ok {
			t.Error("the container's cached listing should invalidate")
		}
		if _, ok := s.Get(listing, "member-key"); ok {
			t.Error("the member's cached listing (the \"child cache\") should invalidate too")
		}
	})
}
