package analysis

import (
	"fmt"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

func TestListNodeFoldsSlashNamesIntoDirectories(t *testing.T) {
	root := carve.Dir("pkg", []*carve.Node{
		carve.FromBytes("a/b/x.txt", []byte("x")),
		carve.FromBytes("a/y.txt", []byte("y")),
		carve.FromBytes("a/b/z.txt", []byte("z")),
		carve.FromBytes("top.txt", []byte("t")),
	})
	l, err := ListNode(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 2 || l.Entries[0].Name != "a" || !l.Entries[0].Dir || l.Entries[1].Name != "top.txt" {
		t.Fatalf("root: %+v", l.Entries)
	}
	a, err := Open(l.Entries[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != 2 || a.Entries[0].Name != "b" || a.Entries[1].Name != "y.txt" {
		t.Fatalf("a: %+v", a.Entries)
	}
	b, err := a.Refresh(nil)
	if err != nil || len(b.Entries) != 2 {
		t.Fatalf("refresh: %v %+v", err, b)
	}
	sub, _ := Open(a.Entries[0], nil)
	if len(sub.Entries) != 2 || sub.Entries[0].Name != "x.txt" {
		t.Fatalf("a/b: %+v", sub.Entries)
	}
}

// rawKernel is a header-less ARM kernel the way a vendor builds it: a few
// instructions, a long padding, and only then the banner and a kernel message.
func rawKernel() []byte {
	b := []byte{0x46, 0x12, 0x04, 0xeb}
	b = append(b, make([]byte, 200<<10)...) // more than any head listing reads
	b = append(b, "Linux version 4.14.202-tcc (b@h) (gcc version 9.2.1) #1 PREEMPT Fri Jan 6 05:40:02 UTC 2023\n"...)
	b = append(b, "\x00Kernel panic - not syncing: "...)
	return append(b, make([]byte, 4096)...)
}

func TestListingLabelsARawKernelByReadingIt(t *testing.T) {
	armFirmware := append([]byte{0x01, 0x00, 0x00, 0xea}, make([]byte, 5000)...) // ARM code, no banner
	root := carve.Dir("pkg", []*carve.Node{
		carve.FromBytes("a7s_boot", rawKernel()),
		carve.FromBytes("mcu.bin", armFirmware),
		carve.FromBytes("blob.bin", make([]byte, 6000)),
	})
	l, err := ListNode(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range l.Entries {
		got[e.Name] = e.Label
	}
	if got["a7s_boot"] != "ARM Linux kernel" {
		t.Errorf("kernel labelled %q", got["a7s_boot"])
	}
	if got["mcu.bin"] != "unknown" || got["blob.bin"] != "unknown" {
		t.Errorf("others: %v", got)
	}
}

// A level of ARM firmware is not read whole to list it: only a few files are probed.
func TestListingProbesAreBounded(t *testing.T) {
	var kids []*carve.Node
	for i := 0; i < deepProbesPerLevel+4; i++ {
		kids = append(kids, carve.FromBytes(fmt.Sprintf("k%02d", i), rawKernel()))
	}
	l, err := ListNode(carve.Dir("pkg", kids))
	if err != nil {
		t.Fatal(err)
	}
	labelled := 0
	for _, e := range l.Entries {
		if e.Label == "ARM Linux kernel" {
			labelled++
		}
	}
	if labelled != deepProbesPerLevel {
		t.Errorf("%d labelled by a full read, want the bound %d", labelled, deepProbesPerLevel)
	}
}
