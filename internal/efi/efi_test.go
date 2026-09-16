package efi

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"strings"
	"testing"
)

// buildFV assembles a minimal firmware volume around the given file bodies.
func buildFV(files ...[]byte) []byte {
	const hdrLen = 72
	body := bytes.Join(files, nil)
	fv := make([]byte, hdrLen+len(body))
	copy(fv[16:32], make([]byte, 16))    // filesystem GUID (zeroes are fine here)
	copy(fv[sigOffset:], []byte("_FVH")) // signature at +40
	binary.LittleEndian.PutUint64(fv[32:], uint64(len(fv)))
	binary.LittleEndian.PutUint16(fv[48:], hdrLen)
	copy(fv[hdrLen:], body)
	return fv
}

// ffsFile builds one FFS file: 24-byte header then the given sections.
func ffsFile(guid []byte, typ byte, sections ...[]byte) []byte {
	body := bytes.Join(sections, nil)
	size := fileHeaderLen + len(body)
	f := make([]byte, size)
	copy(f, guid)
	f[18] = typ
	f[20], f[21], f[22] = byte(size), byte(size>>8), byte(size>>16)
	copy(f[fileHeaderLen:], body)
	// FFS files are 8-byte aligned within a volume.
	if pad := (8 - size%8) % 8; pad != 0 {
		f = append(f, make([]byte, pad)...)
	}
	return f
}

func section(typ byte, payload []byte) []byte {
	size := sectionHeaderLen + len(payload)
	s := make([]byte, size)
	s[0], s[1], s[2] = byte(size), byte(size>>8), byte(size>>16)
	s[3] = typ
	copy(s[sectionHeaderLen:], payload)
	return s
}

func uiSection(name string) []byte {
	b := make([]byte, 0, len(name)*2+2)
	for _, r := range name {
		b = append(b, byte(r), byte(r>>8))
	}
	return section(sectionUserface, append(b, 0, 0))
}

func guidBytes(b ...byte) []byte {
	g := make([]byte, 16)
	copy(g, b)
	return g
}

func TestVolumesRejectsStraySignature(t *testing.T) {
	fv := buildFV(ffsFile(guidBytes(1), 0x07, uiSection("X"), section(sectionPE32, []byte("PE"))))
	// A bare "_FVH" in data must not be mistaken for a volume header.
	img := append([]byte("junk_FVHmore junk padding here to be safe"), fv...)
	vols := Volumes(img)
	if len(vols) != 1 {
		t.Fatalf("expected exactly the real volume, got %d", len(vols))
	}
	if vols[0].Size != len(fv) {
		t.Errorf("size: got %d want %d", vols[0].Size, len(fv))
	}
}

func TestExtractNamesFromUISection(t *testing.T) {
	fv := buildFV(
		ffsFile(guidBytes(0xaa), 0x07, uiSection("ArmCpuDxe"), section(sectionPE32, []byte("BODY"))),
	)
	mods, err := Extract(fv)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 {
		t.Fatalf("got %d modules", len(mods))
	}
	if mods[0].Name != "ArmCpuDxe" {
		t.Errorf("name: %q", mods[0].Name)
	}
	if string(mods[0].Data) != "BODY" {
		t.Errorf("data should be the PE32 body, got %q", mods[0].Data)
	}
}

// A pad file has an all-0xff GUID but a real size; it must not be read as the
// end of the volume, or every module after it is lost.
func TestPadFileDoesNotTruncateVolume(t *testing.T) {
	pad := ffsFile(bytes.Repeat([]byte{0xff}, 16), fileTypePad, make([]byte, 20))
	real := ffsFile(guidBytes(0xbb), 0x07, uiSection("AfterPad"), section(sectionPE32, []byte("Z")))
	mods, err := Extract(buildFV(pad, real))
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 || mods[0].Name != "AfterPad" {
		t.Fatalf("module after pad file was lost: %+v", mods)
	}
}

// Erased flash (0xff including the size field) does end the volume.
func TestBlankTailEndsVolume(t *testing.T) {
	real := ffsFile(guidBytes(0xcc), 0x07, uiSection("First"), section(sectionPE32, []byte("Q")))
	fv := buildFV(real, bytes.Repeat([]byte{0xff}, 64))
	mods, err := Extract(fv)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 || mods[0].Name != "First" {
		t.Fatalf("got %+v", mods)
	}
}

// xbl wraps its nested volume in a Qualcomm GUID that is really gzip.
func TestDescendsGzipNestedVolume(t *testing.T) {
	inner := buildFV(ffsFile(guidBytes(0xdd), 0x07, uiSection("Inner"), section(sectionPE32, []byte("I"))))
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write(inner)
	w.Close()

	payload := make([]byte, 20+gz.Len())
	copy(payload, qcomGzipGUID)
	binary.LittleEndian.PutUint16(payload[16:], lzmaGUIDDefinedHdr) // data offset
	binary.LittleEndian.PutUint16(payload[18:], 1)                  // processing required
	copy(payload[20:], gz.Bytes())

	outer := buildFV(ffsFile(guidBytes(0xee), fileTypeFVImage, section(sectionGUIDDefined, payload)))
	mods, err := Extract(outer)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 || mods[0].Name != "Inner" {
		t.Fatalf("nested gzip volume not descended: %+v", mods)
	}
}

// An unknown compressor must not abandon the volume: the container file is kept
// as-is so the caller still sees something.
func TestUnknownCompressorKeepsRawFile(t *testing.T) {
	payload := make([]byte, 40)
	copy(payload, guidBytes(0x99, 0x88)) // not a compressor we know
	binary.LittleEndian.PutUint16(payload[16:], lzmaGUIDDefinedHdr)
	fv := buildFV(ffsFile(guidBytes(0xff, 0x01), fileTypeFVImage, section(sectionGUIDDefined, payload)))
	mods, err := Extract(fv)
	if err != nil {
		t.Fatalf("unknown compressor should not error: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("expected the raw container, got %d modules", len(mods))
	}
}

func TestLoadGUIDNamesAndApply(t *testing.T) {
	csv := `# comment
guid,name,module_type
8AF09F13-44C5-96EC-1437-DD899CB5EE5D,XBLCore,SEC

bad-line-without-comma
`
	names, err := LoadGUIDNames(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 {
		t.Fatalf("expected 1 mapping, got %d: %v", len(names), names)
	}
	mods := []Module{
		{GUID: "8af09f13-44c5-96ec-1437-dd899cb5ee5d"},
		{GUID: "8af09f13-44c5-96ec-1437-dd899cb5ee5d", Name: "OwnName"},
		{GUID: "unknown-guid"},
	}
	ApplyNames(mods, names)
	if mods[0].Name != "XBLCore" {
		t.Errorf("csv name not applied: %q", mods[0].Name)
	}
	if mods[1].Name != "OwnName" {
		t.Errorf("UI section name must win over the csv: %q", mods[1].Name)
	}
	if mods[2].Name != "" {
		t.Errorf("unknown guid should stay unnamed: %q", mods[2].Name)
	}
}

func TestFilename(t *testing.T) {
	cases := []struct {
		m    Module
		want string
	}{
		{Module{GUID: "abc", Name: "DxeCore", Type: 0x07}, "abc-DxeCore.efi"},
		{Module{GUID: "abc", Type: 0x07}, "abc.efi"},
		{Module{GUID: "abc", Name: "a/b c", Type: 0x07}, "abc-a_b_c.efi"},
		{Module{GUID: "abc", Name: "Vol", Type: fileTypeFVImage}, "abc-Vol.fv"},
	}
	for _, c := range cases {
		if got := c.m.Filename(); got != c.want {
			t.Errorf("Filename() = %q want %q", got, c.want)
		}
	}
}
