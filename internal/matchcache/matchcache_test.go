package matchcache

import (
	"testing"
	"time"
)

type answer struct {
	Commit string
	Note   string
}

func TestPutGetExpiry(t *testing.T) {
	c := New(t.TempDir())
	k := Key("sweep", "repo", "v1")
	var got answer
	if c.Get(k, &got) {
		t.Fatal("a hit on an empty cache")
	}
	c.Put(k, time.Hour, answer{"abc", "closest"})
	if !c.Get(k, &got) || got != (answer{"abc", "closest"}) {
		t.Fatalf("got %+v", got)
	}
	c.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if c.Get(k, &got) {
		t.Error("an expired answer was served")
	}
}

func TestKeys(t *testing.T) {
	if Key("a", "b") == Key("ab") || Key("a", "b") == Key("b", "a") {
		t.Error("parts run together or ignore order")
	}
	x := map[string]bool{"1": true, "2": true, "3": true}
	y := map[string]bool{"3": true, "1": true, "2": true}
	if SetKey(x) != SetKey(y) {
		t.Error("a set's key depends on map order")
	}
	if SetKey(x) == SetKey(map[string]bool{"1": true, "2": true}) {
		t.Error("different sets share a key")
	}
}

func TestUnwritableCacheIsNotAnError(t *testing.T) {
	c := New("/proc/definitely/not/writable")
	c.Put("k", time.Hour, answer{}) // must not panic
	var a answer
	if c.Get("k", &a) {
		t.Error("hit on an unwritable cache")
	}
}
