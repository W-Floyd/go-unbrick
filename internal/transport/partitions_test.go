package transport

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// fakeReader is a transport that hands back whatever was staged for a
// partition, and a failure for anything else.
type fakeReader struct {
	data    map[string][]byte
	reads   []string
	budgets []uint64
}

func (f *fakeReader) ReadPartition(p Partition, budget uint64) ([]byte, error) {
	f.reads = append(f.reads, p.Name)
	f.budgets = append(f.budgets, budget)
	if d, ok := f.data[p.Name]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("reading %s: permission denied", p.Name)
}

func (f *fakeReader) ReadCost() int { return 1 }

// recognizer that claims anything beginning with MAGIC, so Ingest can be tested
// without any real image format.
var testSource = facts.Key[[]byte]("source:test.image", facts.Fmt(facts.ByteLen))

func testRecognizers() []facts.Recognizer {
	return []facts.Recognizer{func(b *facts.Bag, f facts.File) []string {
		if len(f.Data) < 5 || string(f.Data[:5]) != "MAGIC" {
			return nil
		}
		facts.Set(b, testSource, f.Data, facts.Provenance{Source: f.From, Authority: facts.Attested})
		return []string{testSource.Name()}
	}}
}

func TestIngestRecognizesWhatItReads(t *testing.T) {
	r := &fakeReader{data: map[string][]byte{
		"cid":      []byte("MAGIC cid record"),
		"vbmeta_a": []byte("MAGIC vbmeta"),
		"logo_a":   []byte("not a recognized thing"),
	}}
	parts := []Partition{{Name: "cid"}, {Name: "vbmeta_a"}, {Name: "logo_a"}}

	bag := facts.NewBag()
	set, errs := Ingest(r, "test device", bag, testRecognizers(), parts, DefaultReadCap, nil, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	// Every partition is offered; only what a recognizer claimed is reported.
	if len(set) != 2 || set["cid"] == nil || set["vbmeta_a"] == nil {
		t.Errorf("recognized %v, want cid and vbmeta_a", set)
	}
	if _, ok := set["logo_a"]; ok {
		t.Error("an unrecognized partition was reported as a source")
	}
	// The bytes are in the Bag, each with the partition's provenance.
	if got := len(bag.Values(testSource.Name())); got != 2 {
		t.Errorf("bag holds %d values for the source, want 2", got)
	}
}

// A run that is failing for a reason the next partition will not fix must stop
// and say so, rather than repeat one permission error twenty times.
func TestIngestGivesUpAfterRepeatedFailures(t *testing.T) {
	r := &fakeReader{data: map[string][]byte{"cid": []byte("MAGIC cid")}}
	parts := []Partition{
		{Name: "cid"}, {Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}, {Name: "e"},
	}
	bag := facts.NewBag()
	set, errs := Ingest(r, "test device", bag, testRecognizers(), parts, DefaultReadCap, nil, nil)

	if len(set) != 1 {
		t.Errorf("recognized %v, want just cid", set)
	}
	// Three failures, plus the line that says what was skipped.
	if len(errs) != maxConsecutiveReadFailures+1 {
		t.Fatalf("got %d errors, want %d: %v", len(errs), maxConsecutiveReadFailures+1, errs)
	}
	if got := errs[len(errs)-1].Error(); !contains(got, "giving up on the remaining 2") {
		t.Errorf("last error = %q, want the count of what was skipped", got)
	}
	if len(r.reads) != 4 {
		t.Errorf("attempted %d reads (%v), want to have stopped after 4", len(r.reads), r.reads)
	}
}

// A success between failures resets the count: a single unreadable partition in
// a healthy run is not a reason to abandon the rest.
func TestIngestFailureCountResets(t *testing.T) {
	r := &fakeReader{data: map[string][]byte{
		"cid": []byte("MAGIC 1"), "b": []byte("MAGIC 2"), "d": []byte("MAGIC 3"),
	}}
	parts := []Partition{
		{Name: "cid"}, {Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"},
	}
	bag := facts.NewBag()
	set, errs := Ingest(r, "test device", bag, testRecognizers(), parts, DefaultReadCap, nil, nil)
	if len(set) != 3 {
		t.Errorf("recognized %v, want three partitions", set)
	}
	if len(errs) != 2 {
		t.Errorf("got %d errors, want 2 (a and c): %v", len(errs), errs)
	}
	if len(r.reads) != len(parts) {
		t.Errorf("attempted %d reads, want all %d", len(r.reads), len(parts))
	}
}

func TestIngestReportsProgress(t *testing.T) {
	r := &fakeReader{data: map[string][]byte{"cid": []byte("MAGIC")}}
	var seen []string
	_, _ = Ingest(r, "test", facts.NewBag(), testRecognizers(),
		[]Partition{{Name: "cid"}}, DefaultReadCap, func(i, n int, p Partition) {
			seen = append(seen, fmt.Sprintf("%d/%d %s", i+1, n, p.Name))
		}, nil)
	if len(seen) != 1 || seen[0] != "1/1 cid" {
		t.Errorf("progress = %v", seen)
	}
}

// A size of 0 is "the device would not say", not "empty" — an unrooted adb
// shell cannot read /sys/class/block at all. Such a partition is still selected
// and still read, bounded by the cap.
func TestUnknownSizeIsStillRead(t *testing.T) {
	parts := []Partition{
		{Name: "cid"},                        // size unknown
		{Name: "xbl_a", SizeBytes: 4 << 20},  // known, under the cap
		{Name: "super", SizeBytes: 12 << 30}, // known, over the cap
		{Name: "userdata"},                   // unknown, but not an identity partition
	}
	got := IdentityPartitions(parts, "a", DefaultReadCap)
	var names []string
	for _, p := range got {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "cid,xbl_a" {
		t.Errorf("IdentityPartitions() = %v, want cid and xbl_a", names)
	}

	r := &fakeReader{data: map[string][]byte{"cid": []byte("MAGIC"), "xbl_a": []byte("MAGIC")}}
	_, errs := Ingest(r, "test", facts.NewBag(), testRecognizers(), got, 1<<20, nil, nil)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	// The unknown-size read is bounded by the cap; the known-size one by its own
	// size, so a correctly-sized partition is never over-read.
	if len(r.budgets) != 2 || r.budgets[0] != 1<<20 || r.budgets[1] != 1<<20 {
		t.Errorf("budgets = %v, want the cap for the unknown size and the size (capped) for the known one", r.budgets)
	}
	if b := ReadBudget(Partition{SizeBytes: 4096}, 1<<20); b != 4096 {
		t.Errorf("ReadBudget of a small known size = %d, want its own size", b)
	}
	if b := ReadBudget(Partition{}, 0); b != DefaultReadCap {
		t.Errorf("ReadBudget with no cap = %d, want the default", b)
	}
}

func TestGapIsAWarning(t *testing.T) {
	f := Gap("collecting over ssh", errors.New("section unreadable"))
	if f.Severity != facts.Warn {
		t.Errorf("severity = %v, want warn: a gap is not a failed recon", f.Severity)
	}
	if !contains(f.Message, "collecting over ssh") || !contains(f.Message, "section unreadable") {
		t.Errorf("message = %q, want both what failed and why", f.Message)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
