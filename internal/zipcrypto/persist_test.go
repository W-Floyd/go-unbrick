package zipcrypto

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// A member read to its end once is read there again from its saved checkpoints,
// without the pass over everything before.
func TestPersistedCheckpointsSkipThePass(t *testing.T) {
	plain := make([]byte, 3*checkpointEvery+999)
	rand.New(rand.NewSource(3)).Read(plain)
	enc := Encrypt(plain, []byte("pw"), 7)
	file := filepath.Join(t.TempDir(), "sub", "cp")
	tail := int64(len(plain)) - 100

	first, err := NewReaderAt(bytes.NewReader(enc), int64(len(plain)), []byte("pw"), 7)
	if err != nil {
		t.Fatal(err)
	}
	first.Persist(file)
	buf := make([]byte, 100)
	if _, err := first.ReadAt(buf, tail); err != nil && !bytes.Equal(buf, plain[tail:]) {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("checkpoints not kept: %v", err)
	}

	src := &countingReaderAt{r: bytes.NewReader(enc)}
	again, err := NewReaderAt(src, int64(len(plain)), []byte("pw"), 7)
	if err != nil {
		t.Fatal(err)
	}
	again.Persist(file)
	if again.ID() != first.ID() {
		t.Error("the same member has two ids")
	}
	src.n = 0
	if n, _ := again.ReadAt(buf, tail); n != 100 || !bytes.Equal(buf, plain[tail:tail+100]) {
		t.Fatalf("wrong bytes from saved checkpoints (%d)", n)
	}
	if src.n > 2*checkpointEvery {
		t.Errorf("%d bytes read from the source despite saved checkpoints", src.n)
	}

	// Another member's file is not trusted.
	other := Encrypt(plain, []byte("other"), 7)
	o, _ := NewReaderAt(bytes.NewReader(other), int64(len(plain)), []byte("other"), 7)
	o.Persist(file)
	if _, err := o.ReadAt(buf, tail); err != nil || !bytes.Equal(buf, plain[tail:tail+100]) {
		t.Errorf("a stranger's checkpoints were used: %v", err)
	}
}
