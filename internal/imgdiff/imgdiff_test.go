package imgdiff

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"strings"
	"testing"
)

// elf builds a minimal little-endian ELFCLASS64 image with the given segments.
// Each segment is {flags, payload}; flags nibble 2 at bits 24-27 marks the
// Qualcomm hash segment. Segments are laid out on 4096-byte boundaries, and
// trailing bytes past the last segment sit outside every program header.
type seg struct {
	flags   uint32
	paddr   uint64
	payload []byte
}

func elf(segs []seg, trailer []byte) []byte {
	const phoff, phentsize = 64, 56
	hdr := make([]byte, phoff+phentsize*len(segs))
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint64(hdr[0x20:], phoff)
	binary.LittleEndian.PutUint16(hdr[0x36:], phentsize)
	binary.LittleEndian.PutUint16(hdr[0x38:], uint16(len(segs)))

	body := bytes.NewBuffer(nil)
	base := 4096
	for i, s := range segs {
		off := base + i*4096
		for body.Len()+len(hdr) < off {
			body.WriteByte(0)
		}
		o := phoff + i*phentsize
		binary.LittleEndian.PutUint32(hdr[o+4:], s.flags)
		binary.LittleEndian.PutUint64(hdr[o+8:], uint64(off))
		binary.LittleEndian.PutUint64(hdr[o+24:], s.paddr)
		binary.LittleEndian.PutUint64(hdr[o+32:], uint64(len(s.payload)))
		body.Write(s.payload)
	}
	out := append(hdr, body.Bytes()...)
	return append(out, trailer...)
}

const hashFlags = 2 << 24

func randBytes(n int, seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	r.Read(b)
	return b
}

func TestIdentical(t *testing.T) {
	img := elf([]seg{{hashFlags, 0x1000, []byte("SIG")}, {0, 0x2000, []byte("PAYLOAD")}}, nil)
	r, err := Compare(img, img)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != Identical {
		t.Errorf("got %q want %q", r.Verdict, Identical)
	}
}

// Two builds of one image differ in the hash segment by construction; that must
// not read as a payload change.
func TestResignOnly(t *testing.T) {
	pay := []byte("IDENTICAL PAYLOAD BYTES")
	a := elf([]seg{{hashFlags, 0x1000, []byte("SIGNATURE-A")}, {0, 0x2000, pay}}, nil)
	b := elf([]seg{{hashFlags, 0x1000, []byte("SIGNATURE-B")}, {0, 0x2000, pay}}, nil)
	r, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != ResignOnly {
		t.Fatalf("got %q want %q", r.Verdict, ResignOnly)
	}
	for _, s := range r.Segments {
		if !s.Hash && s.Differing != 0 {
			t.Errorf("payload segment should be identical, got %d differing", s.Differing)
		}
	}
}

func TestPayloadChanged(t *testing.T) {
	sig := []byte("SIG")
	a := elf([]seg{{hashFlags, 0x1000, sig}, {0, 0x2000, []byte("AAAAAAAAAAAAAAAA")}}, nil)
	b := elf([]seg{{hashFlags, 0x1000, sig}, {0, 0x2000, []byte("AAAABBBBAAAAAAAA")}}, nil)
	r, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != Changed {
		t.Errorf("got %q want %q", r.Verdict, Changed)
	}
}

// The build stamp lives past the last program header. Comparing only segments
// would report two different builds as indistinguishable.
func TestOutsideSegmentStamp(t *testing.T) {
	pay := []byte("SAME PAYLOAD")
	sig := []byte("SAME SIG")
	a := elf([]seg{{hashFlags, 0x1000, sig}, {0, 0x2000, pay}}, []byte("MBM-3.0-fogona-aaaaaaa-250831"))
	b := elf([]seg{{hashFlags, 0x1000, sig}, {0, 0x2000, pay}}, []byte("MBM-3.0-fogona-bbbbbbb-240823"))
	r, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if r.OutsideDiffering == 0 {
		t.Fatal("a differing build stamp outside all segments was not detected")
	}
	if r.Verdict != ResignOnly {
		t.Errorf("verdict: got %q want %q", r.Verdict, ResignOnly)
	}
	if !strings.Contains(r.StampA, "250831") || !strings.Contains(r.StampB, "240823") {
		t.Errorf("stamps not recovered whole: %q / %q", r.StampA, r.StampB)
	}
}

// High-entropy runs are flagged opaque so a caller does not read a big byte
// count over compressed or key material as a big semantic change.
func TestOpaqueClassification(t *testing.T) {
	sig := []byte("SIG")
	a := elf([]seg{{hashFlags, 0x1000, sig}, {0, 0x2000, randBytes(4096, 1)}}, nil)
	b := elf([]seg{{hashFlags, 0x1000, sig}, {0, 0x2000, randBytes(4096, 2)}}, nil)
	r, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range r.Segments {
		if s.Hash || s.Differing == 0 {
			continue
		}
		if !s.Opaque() {
			t.Errorf("random payload should classify opaque, runs=%+v", s.Runs)
		}
	}

	// Structured data must not be swept into the same bucket.
	lowA := bytes.Repeat([]byte("ABCD"), 1024)
	lowB := bytes.Repeat([]byte("ABCE"), 1024)
	r2, _ := Compare(
		elf([]seg{{hashFlags, 0x1000, sig}, {0, 0x2000, lowA}}, nil),
		elf([]seg{{hashFlags, 0x1000, sig}, {0, 0x2000, lowB}}, nil),
	)
	for _, s := range r2.Segments {
		if !s.Hash && s.Differing > 0 && s.Opaque() {
			t.Error("low-entropy data should not classify as opaque")
		}
	}
}

// A reordered name table shifts every byte after it; comparing names as a set
// is what distinguishes reordering from real change.
func TestNameTableReorder(t *testing.T) {
	names := []string{"OEM_keystore_enable_rpmb", "OEM_tz_log_level", "fingerprint_qsee_spidev_id", "client_00"}
	build := func(order []int) []byte {
		buf := bytes.NewBuffer(nil)
		for _, i := range order {
			buf.WriteString(names[i])
			buf.WriteByte(0)
		}
		return buf.Bytes()
	}
	sig := []byte("SIG")
	a := elf([]seg{{hashFlags, 0x1000, sig}, {0, 0x2000, build([]int{0, 1, 2, 3})}}, nil)
	b := elf([]seg{{hashFlags, 0x1000, sig}, {0, 0x2000, build([]int{3, 2, 1, 0})}}, nil)
	r, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, s := range r.Segments {
		if s.Hash || s.Differing == 0 {
			continue
		}
		found = true
		if !s.NamesEqual {
			t.Errorf("same names reordered should compare equal as a set: %v vs %v", s.NamesA, s.NamesB)
		}
		if s.NamesOrdered {
			t.Error("reordered table should not report the same order")
		}
	}
	if !found {
		t.Fatal("expected a differing payload segment")
	}
}

// Images whose segment layouts do not correspond cannot be diffed per segment;
// saying so is better than reporting a meaningless number.
func TestIncomparableLayouts(t *testing.T) {
	a := elf([]seg{{hashFlags, 0x1000, []byte("SIG")}, {0, 0x2000, []byte("SHORT")}}, nil)
	b := elf([]seg{{hashFlags, 0x1000, []byte("SIG")}, {0, 0x2000, []byte("MUCH LONGER PAYLOAD")}}, nil)
	r, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != Incomparable {
		t.Errorf("got %q want %q", r.Verdict, Incomparable)
	}

	c := elf([]seg{{hashFlags, 0x1000, []byte("SIG")}}, nil)
	r2, _ := Compare(a, c)
	if r2.Verdict != Incomparable {
		t.Errorf("differing segment counts: got %q", r2.Verdict)
	}
}

func TestNonELF(t *testing.T) {
	if _, err := Compare([]byte("not an elf"), []byte("nor this")); err == nil {
		t.Error("expected an error for non-ELF input")
	}
}
