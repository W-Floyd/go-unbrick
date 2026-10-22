package vendor

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func TestHKMCArtifact(t *testing.T) {
	conb := make([]byte, 0x28)
	copy(conb, "ConB")
	conb = append(conb, 'M', 0, 'D', 0, '.', 0, 'x', 0, 0, 0)
	// A real one-section header (see internal/npkg): magic, version, count=1,
	// a 20-byte timestamp at 0x0C, then one {tag, offset, size} row at 0x20
	// naming the rest of this buffer as the one section.
	prnm := make([]byte, 0x30)
	copy(prnm, "PRNM")
	binary.LittleEndian.PutUint32(prnm[4:], 1000)
	binary.LittleEndian.PutUint32(prnm[8:], 1)
	copy(prnm[0x0C:], "2025/11/26 09:05:00")
	binary.LittleEndian.PutUint32(prnm[0x24:], 0x2c)                   // offset: header end
	binary.LittleEndian.PutUint32(prnm[0x28:], uint32(len(prnm))-0x2c) // size: rest of the buffer
	ffu := make([]byte, 0x30)
	copy(ffu[0x20:], "FQT00RD")
	for _, c := range []struct {
		name, label, detail string
		data                []byte
	}{
		{"x.bin", "navi config (ConB)", "MD.x", conb},
		{"x.npkg", "navi package (PRNM)", "", prnm}, // detail comes from ArtifactReport now, not here
		{"gps_module.bin", "Trimble GPS firmware (TRMB)", "", []byte("TRMB\x01")},
		{"ffu/ffu_sw.bin", "Micron FFU firmware", "FQT00RD", ffu},
	} {
		got, ok := hkmcArtifact(c.name, c.data)
		if !ok || got.Label != c.label || got.Detail != c.detail {
			t.Errorf("%s: got %+v ok=%v", c.name, got, ok)
		}
	}
	if _, ok := hkmcArtifact("ffu_sw.bin", make([]byte, 0x30)); ok {
		t.Error("ffu_sw.bin without FQT matched")
	}
}

func TestHKMCArtifactReportPRNM(t *testing.T) {
	prnm := make([]byte, 0x30)
	copy(prnm, "PRNM")
	binary.LittleEndian.PutUint32(prnm[4:], 1000)
	binary.LittleEndian.PutUint32(prnm[8:], 1)
	copy(prnm[0x0C:], "2025/11/26 09:05:00")
	binary.LittleEndian.PutUint32(prnm[0x24:], 0x2c)
	binary.LittleEndian.PutUint32(prnm[0x28:], uint32(len(prnm))-0x2c)
	dir := t.TempDir()
	path := dir + "/x.npkg"
	if err := os.WriteFile(path, prnm, 0o644); err != nil {
		t.Fatal(err)
	}
	lines := hkmc{}.ArtifactReport(path, prnm)
	if len(lines) != 2 || !strings.Contains(lines[0], "1 section") || !strings.Contains(lines[1], "tag 0x00000000") {
		t.Errorf("%+v", lines)
	}
	if got := (hkmc{}).ArtifactReport(path, []byte("notPRNM")); got != nil {
		t.Errorf("non-PRNM head should report nothing: %+v", got)
	}
}
