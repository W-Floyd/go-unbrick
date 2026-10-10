package vendor

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// mtkPart is one MediaTek image part: a 512-byte header, then size bytes.
func mtkPart(name string, size int, last bool) []byte {
	h := make([]byte, 512)
	copy(h, mtkImageMagic)
	binary.LittleEndian.PutUint32(h[4:], uint32(size))
	copy(h[8:], name)
	copy(h[0x30:], mtkExtMagic)
	binary.LittleEndian.PutUint32(h[0x34:], 512)
	if last {
		binary.LittleEndian.PutUint32(h[0x40:], 1)
	}
	binary.LittleEndian.PutUint32(h[0x44:], 16)
	return append(h, make([]byte, (size+15)/16*16)...)
}

func TestMTKParts(t *testing.T) {
	img := append(append(mtkPart("md1rom", 100, false), mtkPart("cert1", 16, false)...), mtkPart("cert2", 33, true)...)
	if got, want := mtkParts(img), []string{"md1rom", "cert1", "cert2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("parts = %v, want %v", got, want)
	}
}

func TestFSGVariants(t *testing.T) {
	img := make([]byte, 8+3*64)
	copy(img, "FSGADAPT")
	for i, id := range []string{"P89990AA1", "P89990AA1_2"} {
		o := 8 + i*64
		copy(img[o:], "FSG_000"+string(rune('1'+i)))
		copy(img[o+8:], id+"      ")
	}
	if got, want := fsgVariants(img), []string{"P89990AA1", "P89990AA1_2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("variants = %v, want %v", got, want)
	}
	if fsgVariants([]byte("not an fsg image")) != nil {
		t.Error("non-FSG data parsed")
	}
}
