package bootimg

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/pierrec/lz4/v4"
)

// newcEntry builds one newc cpio record.
func newcEntry(name string, mode uint32, data []byte) []byte {
	var b bytes.Buffer
	b.WriteString("070701")
	fields := []uint32{
		0, mode, 0, 0, 1, 0, uint32(len(data)), 0, 0, 0, 0,
		uint32(len(name) + 1), 0,
	}
	for _, f := range fields {
		fmt.Fprintf(&b, "%08X", f)
	}
	b.WriteString(name)
	b.WriteByte(0)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	b.Write(data)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

// makeCpio assembles a newc archive from name->contents, closed with TRAILER!!!.
func makeCpio(files map[string][]byte) []byte {
	var b bytes.Buffer
	for name, data := range files {
		b.Write(newcEntry(name, sIFREG|0o755, data))
	}
	b.Write(newcEntry("TRAILER!!!", 0, nil))
	return b.Bytes()
}

func gz(b []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

func lz4c(b []byte) []byte {
	var out bytes.Buffer
	w := lz4.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

// makeBootV4 wraps a ramdisk blob in an ANDROID! v4 header.
func makeBootV4(ramdisk []byte) []byte {
	hdr := make([]byte, pageV3)
	copy(hdr, bootMagic)
	binary.LittleEndian.PutUint32(hdr[8:], 0)             // kernel_size
	binary.LittleEndian.PutUint32(hdr[12:], uint32(len(ramdisk)))
	binary.LittleEndian.PutUint32(hdr[20:], 1580)         // header_size (<page)
	binary.LittleEndian.PutUint32(hdr[40:], 4)            // header_version
	body := make([]byte, len(ramdisk))
	copy(body, ramdisk)
	for len(body)%pageV3 != 0 {
		body = append(body, 0)
	}
	return append(hdr, body...)
}

func TestCpioRoundTrip(t *testing.T) {
	cpio := makeCpio(map[string][]byte{
		"system/bin/fastbootd": []byte("\x7fELF-fake"),
		"init":                 []byte("#!/init"),
	})
	entries, err := ParseCpio(cpio)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	e, ok := Find(entries, "fastbootd")
	if !ok {
		t.Fatal("fastbootd not found by basename")
	}
	if string(e.Data) != "\x7fELF-fake" || !e.IsReg {
		t.Errorf("fastbootd entry: %+v", e)
	}
	if _, ok := Find(entries, "system/bin/fastbootd"); !ok {
		t.Error("fastbootd not found by full path")
	}
}

func TestParseBootV4EachCodec(t *testing.T) {
	cpio := makeCpio(map[string][]byte{"system/bin/fastbootd": []byte("payload")})
	cases := map[string][]byte{
		"gzip": gz(cpio),
		"lz4":  lz4c(cpio),
		"none": cpio, // a plain, uncompressed ramdisk
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			im, err := Parse(makeBootV4(blob))
			if err != nil {
				t.Fatal(err)
			}
			if im.HeaderVersion != 4 || im.Magic != bootMagic {
				t.Fatalf("header: %+v", im)
			}
			rds := im.Ramdisks()
			if len(rds) != 1 {
				t.Fatalf("want 1 ramdisk, got %d", len(rds))
			}
			plain, _, err := DecompressRamdisk(rds[0].Data)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := ParseCpioConcat(plain)
			if err != nil {
				t.Fatal(err)
			}
			if e, ok := Find(entries, "fastbootd"); !ok || string(e.Data) != "payload" {
				t.Errorf("fastbootd not recovered through %s", name)
			}
		})
	}
}

func TestConcatenatedRamdisk(t *testing.T) {
	// Android lays two cpio archives end to end (generic + vendor overlay).
	a := makeCpio(map[string][]byte{"init": []byte("a")})
	b := makeCpio(map[string][]byte{"system/bin/fastbootd": []byte("b")})
	entries, err := ParseCpioConcat(append(a, b...))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Find(entries, "init"); !ok {
		t.Error("first archive lost")
	}
	if _, ok := Find(entries, "fastbootd"); !ok {
		t.Error("second concatenated archive lost")
	}
}

func TestParseRejectsNonBootImage(t *testing.T) {
	if _, err := Parse([]byte("not a boot image at all")); err == nil {
		t.Error("expected error on non-boot bytes")
	}
}

func TestDetectCodec(t *testing.T) {
	for want, blob := range map[Codec][]byte{
		CodecGzip: gz([]byte("x")),
		CodecLZ4:  lz4c([]byte("x")),
		CodecNone: []byte("070701abc"),
	} {
		if got := DetectCodec(blob); got != want {
			t.Errorf("codec: got %q want %q", got, want)
		}
	}
	if got := DetectCodec([]byte{0, 1, 2, 3}); got != "" {
		t.Errorf("unknown blob should detect no codec, got %q", got)
	}
}
