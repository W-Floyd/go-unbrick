package telechips

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// image builds a signed-wrapper image around a payload with the given strings.
func image(t *testing.T, signed bool, strs ...string) []byte {
	t.Helper()
	le := binary.LittleEndian
	var payload bytes.Buffer
	hdr := make([]byte, 0x90)
	le.PutUint32(hdr[0:], 0x14000024) // b 0x90
	le.PutUint32(hdr[4:], 0xffff0106)
	copy(hdr[8:], "Ver:1234")
	le.PutUint32(hdr[0x60:], 0x30000000)
	copy(hdr[0x68:], "BOOT")
	le.PutUint32(hdr[0x70:], 0x30000000)
	le.PutUint32(hdr[0x78:], 0xa3930)
	le.PutUint32(hdr[0x88:], 0xb5178)
	payload.Write(hdr)
	for _, s := range strs {
		payload.WriteString(s)
		payload.WriteByte(0)
	}
	img := make([]byte, 0x1000+payload.Len()+0x100)
	copy(img, "CERT")
	if signed {
		img[0x80] = 0xaa
	}
	copy(img[0x100:], "HDR\x00")
	le.PutUint32(img[0x104:], uint32(payload.Len()))
	le.PutUint32(img[0x108:], 0x1000)
	copy(img[0x110:], "803xA53-BL3")
	copy(img[0x120:], "0.0.0")
	le.PutUint32(img[0x130:], 0x30000000)
	copy(img[0x160:], bytes.Repeat([]byte{0x5a}, 32))
	copy(img[0x1000:], payload.Bytes())
	return img
}

func TestParse(t *testing.T) {
	img := image(t, false,
		"U-Boot 2020.01 (Jan 07 2026 - 17:20:41 +0900)",
		"aarch64-none-linux-gnu-gcc (GNU Toolchain for the A-profile Architecture 9.2-2019.12 (arm-9.10)) 9.2.1 20191025",
		"bootdelay=0", "board_id=2000", "bootcmd=x", "bootcmd=smc reset_type rst_type; run loadfdtpart",
		"lib/libavb/avb_rsa.c", "Android Fastboot", "flashing unlock", "noise string")
	if !IsImage(img) || IsImage(img[:0x100]) || IsImage([]byte("CERT")) {
		t.Fatal("IsImage")
	}
	im, err := Parse(img)
	if err != nil {
		t.Fatal(err)
	}
	if im.Name != "803xA53-BL3" || im.Version != "0.0.0" || im.LoadAddr != 0x30000000 || im.PayloadOff != 0x1000 || im.Signed {
		t.Errorf("wrapper: %+v", im)
	}
	if im.Tag != "BOOT" || im.Base != 0x30000000 || im.CodeSize != 0xa3930 || im.EndSize != 0xb5178 || im.StageVer != "Ver:1234" {
		t.Errorf("stage header: %+v", im)
	}
	if im.UBoot != "U-Boot 2020.01 (Jan 07 2026 - 17:20:41 +0900)" || !strings.HasPrefix(im.Compiler, "aarch64-none-linux-gnu-gcc") {
		t.Errorf("banner: %q / %q", im.UBoot, im.Compiler)
	}
	if im.Env["bootdelay"] != "0" || im.Env["board_id"] != "2000" || !strings.HasPrefix(im.Env["bootcmd"], "smc reset_type") {
		t.Errorf("env: %v", im.Env)
	}
	if got := strings.Join(im.Features, ","); got != "Android Verified Boot (libavb),fastboot,flashing unlock" {
		t.Errorf("features: %s", got)
	}
	if im2, _ := Parse(image(t, true, "x")); !im2.Signed {
		t.Error("a CERT block with content is not marked signed")
	}
	if _, err := Parse(img[:0x1000]); err == nil {
		t.Error("a truncated payload was accepted")
	}
}

// With UNBRICK_TELECHIPS_SAMPLE pointing at a real bl3 image, it is read too.
func TestRealImage(t *testing.T) {
	p := os.Getenv("UNBRICK_TELECHIPS_SAMPLE")
	if p == "" {
		t.Skip("UNBRICK_TELECHIPS_SAMPLE not set")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	im, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", im)
	if im.UBoot == "" || len(im.Env) == 0 || len(im.Features) == 0 {
		t.Errorf("nothing found in a real image: %+v", im)
	}
}
