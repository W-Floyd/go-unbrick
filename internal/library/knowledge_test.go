package library

import (
	"os"
	"testing"

	yaml "go.yaml.in/yaml/v4"
)

func TestLearnAccumulates(t *testing.T) {
	l := Open(t.TempDir())
	// First sighting.
	added, err := l.Learn("motorola", "fogona", map[string]string{"soc": "SM6225", "cid": "0x0032"})
	if err != nil || len(added) != 2 {
		t.Fatalf("first: added=%v err=%v", added, err)
	}
	// Second sighting, one new carrier value.
	added, err = l.Learn("motorola", "fogona", map[string]string{"soc": "SM6225", "cid": "0x0033"})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != "cid=0x0033" {
		t.Fatalf("second: expected one new cid value, got %v", added)
	}
	// A repeat teaches nothing.
	added, _ = l.Learn("motorola", "fogona", map[string]string{"soc": "SM6225"})
	if len(added) != 0 {
		t.Fatalf("repeat learned %v", added)
	}
}

func TestLearnMatchingSets(t *testing.T) {
	l := Open(t.TempDir())
	// Two vantages see different halves.
	l.Learn("motorola", "fogona", map[string]string{"carrier": "tracfone"})
	l.Learn("motorola", "fogona", map[string]string{"cid": "0x0033"})
	// Now one recon sees both together — a new matching set, though each value
	// was already known.
	added, _ := l.Learn("motorola", "fogona", map[string]string{"carrier": "tracfone", "cid": "0x0033"})
	if len(added) != 1 || added[0] != "(new matching set)" {
		t.Fatalf("expected a new matching set, got %v", added)
	}
	// The two partial sets it subsumes are gone; only the joined set remains.
	k := &Knowledge{}
	b, _ := os.ReadFile(l.knowledgePath("motorola", "fogona"))
	yaml.Unmarshal(b, k)
	if len(k.Observations) != 1 || k.Observations[0]["carrier"] != "tracfone" || k.Observations[0]["cid"] != "0x0033" {
		t.Fatalf("expected one joined observation, got %v", k.Observations)
	}
	// Re-seeing the subset teaches nothing.
	if added, _ := l.Learn("motorola", "fogona", map[string]string{"carrier": "tracfone"}); len(added) != 0 {
		t.Fatalf("subset re-learn changed something: %v", added)
	}
}

// A subset of a known larger set is ambiguous — it may be that variant seen
// partially, or a different one sharing those fields — so it must neither spawn
// its own set nor be recorded as new.
func TestLearnSubsetIsAmbiguousAndDropped(t *testing.T) {
	l := Open(t.TempDir())
	l.Learn("motorola", "fogona", map[string]string{"carrier": "tracfone", "cid": "0x0033", "region": "US"})
	// A later vantage sees only carrier+region — consistent with the set above,
	// but also with an unseen different-CID variant.
	added, _ := l.Learn("motorola", "fogona", map[string]string{"carrier": "tracfone", "region": "US"})
	if len(added) != 0 {
		t.Fatalf("ambiguous subset recorded something: %v", added)
	}
	k := &Knowledge{}
	b, _ := os.ReadFile(l.knowledgePath("motorola", "fogona"))
	yaml.Unmarshal(b, k)
	if len(k.Observations) != 1 {
		t.Fatalf("subset must not create a second set; got %d observations", len(k.Observations))
	}
}
