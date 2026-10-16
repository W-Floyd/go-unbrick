package vendor

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"testing"
)

func TestParseUpdateInfo(t *testing.T) {
	if got := ParseUpdateInfo([]byte("SWVERSION - ECOKMC.USA.1001.V015.012\n\n./system\n")); got != "ECOKMC.USA.1001.V015.012" {
		t.Errorf("got %q", got)
	}
	if ParseUpdateInfo([]byte("nothing")) != "" {
		t.Error("matched without SWVERSION")
	}
}

func TestParseModemVersion(t *testing.T) {
	got := ParseModemVersion([]byte("boot:01J_BBOOT, modem:01T_WVZW, gw:37\n"))
	if want := "01T_WVZW [boot 01J_BBOOT, gw 37]"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if ParseModemVersion([]byte("boot:x")) != "" {
		t.Error("matched without modem")
	}
}

func TestZImageKernelVersion(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte("junk\x00Linux version 3.18.24-tcc (a@b) #1\nmore"))
	w.Close()
	z := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(z[0x24:], zImageMagic)
	z = append(z, gz.Bytes()...)
	z = append(z, 0, 0, 0, 0)
	if got := ZImageKernelVersion(z); got != "Linux version 3.18.24-tcc (a@b) #1" {
		t.Errorf("got %q", got)
	}
	if ZImageKernelVersion(gz.Bytes()) != "" {
		t.Error("matched a non-zImage")
	}
}
