package vendor

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/bootimg"
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
	binary.LittleEndian.PutUint32(z[0x24:], bootimg.ZImageMagic)
	z = append(z, gz.Bytes()...)
	z = append(z, 0, 0, 0, 0)
	if got := ZImageKernelVersion(z); got != "Linux version 3.18.24-tcc (a@b) #1" {
		t.Errorf("got %q", got)
	}
	if ZImageKernelVersion(gz.Bytes()) != "" {
		t.Error("matched a non-zImage")
	}
}

func TestParseSplash(t *testing.T) {
	b := make([]byte, 16+2*52)
	copy(b, splashMagic)
	binary.LittleEndian.PutUint32(b[8:], 2)
	for i, name := range []string{"hyundai_1280x720", "kia_1920x720"} {
		e := b[16+i*52:]
		copy(e, name)
		binary.LittleEndian.PutUint32(e[20:], uint32(2048+i*100))
		binary.LittleEndian.PutUint32(e[24:], 100)
		binary.LittleEndian.PutUint32(e[28:], 1280)
		copy(e[40:], "JPEG")
	}
	imgs, err := ParseSplash(b)
	if err != nil || len(imgs) != 2 || imgs[1].Name != "kia_1920x720" || imgs[1].Off != 2148 || imgs[0].Type != "JPEG" {
		t.Fatalf("got %+v, %v", imgs, err)
	}
	if _, err := ParseSplash(b[:20]); err == nil {
		t.Error("truncated table parsed")
	}
}

func TestSummarizeKernelConfig(t *testing.T) {
	cfg := "# CONFIG_X is not set\nCONFIG_ARCH_TCC=y\nCONFIG_ARCH_TCC803X=y\nCONFIG_DM_VERITY=y\nCONFIG_SECURITY_SELINUX=y\nCONFIG_OFF=n\n"
	want := "4 options, ARCH_TCC803X, dm-verity, SELinux"
	if got := SummarizeKernelConfig([]byte(cfg)); got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if SummarizeKernelConfig([]byte("# nothing")) != "" {
		t.Error("summarised an empty config")
	}
}
