package bootimg

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

const testBanner = "Linux version 3.18.24-tcc (vmadmin@build-host) (gcc version 4.7 (GCC) ) #1 SMP PREEMPT Thu May 7 09:25:08 KST 2026\n"

const testConfig = "CONFIG_ARM=y\nCONFIG_CPU_V7=y\nCONFIG_ARCH_TCC803X=y\nCONFIG_KERNEL_GZIP=y\nCONFIG_LOCALVERSION=\"-tcc\"\n" +
	"CONFIG_SECURITY_SELINUX=y\nCONFIG_DM_VERITY=y\n# CONFIG_MODULE_SIG is not set\nCONFIG_DEVMEM=y\nCONFIG_CMDLINE=\" \"\n"

// rawKernel is some code, the banner, and an embedded gzip'd config.
func rawKernel(t *testing.T) []byte {
	k := append(bytes.Repeat([]byte{0xe1, 0xa0}, 2000), []byte(testBanner)...)
	k = append(k, make([]byte, 100)...)
	k = append(k, []byte("IKCFG_ST")...)
	k = append(k, gz([]byte(testConfig))...)
	k = append(k, []byte("IKCFG_ED")...)
	return k
}

func TestFindBannerAndConfigHighlights(t *testing.T) {
	b, ok := FindBanner(rawKernel(t))
	if !ok || b.Release != "3.18.24-tcc" || b.Builder != "vmadmin@build-host" || !strings.HasPrefix(b.Compiler, "gcc version 4.7") || !strings.HasPrefix(b.Build, "#1 SMP PREEMPT Thu May 7") {
		t.Errorf("%+v %v", b, ok)
	}
	if _, ok := FindBanner([]byte("no kernel here, Linux version only")); ok {
		t.Error("a banner was invented")
	}
	got := strings.Join(ConfigHighlights([]byte(testConfig)), "\n")
	for _, want := range []string{"built for: ARCH_TCC803X, ARM, CPU_V7", "compression: gzip", "localversion: -tcc", "on: SELinux, dm-verity", "module signing", "present: /dev/mem"} {
		if !strings.Contains(got, want) {
			t.Errorf("highlights lack %q:\n%s", want, got)
		}
	}
}

func TestDescribeAZImage(t *testing.T) {
	stub := make([]byte, 0x400)
	binary.LittleEndian.PutUint32(stub[0x24:], ZImageMagic)
	z := append(stub, gz(rawKernel(t))...)
	binary.LittleEndian.PutUint32(z[0x2c:], uint32(len(z)))
	out := strings.Join(Describe(z), "\n")
	for _, want := range []string{"Kernel: Linux 3.18.24-tcc", "Form: ARM zImage", "payload (gzip) at 0x400", "unpacks to", "Config: embedded (IKCONFIG)", "built for: ARCH_TCC803X"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "appended") {
		t.Errorf("an end that matches the file reads as an appended tree:\n%s", out)
	}
	// An end before the file's: something follows the zImage.
	binary.LittleEndian.PutUint32(z[0x2c:], uint32(len(z)-100))
	if out := strings.Join(Describe(z), "\n"); !strings.Contains(out, "appended device tree?") {
		t.Errorf("data after the declared end is not noticed:\n%s", out)
	}
}

func TestARM64Image(t *testing.T) {
	h := make([]byte, 0x40)
	copy(h, "MZ")
	le := binary.LittleEndian
	le.PutUint64(h[8:], 0x80000)
	le.PutUint64(h[16:], 21<<20)
	le.PutUint64(h[24:], 0xa) // 4K pages, physical placement
	copy(h[0x38:], "ARM\x64")
	le.PutUint32(h[0x3c:], 0x40)
	p, ok := ParseARM64(h)
	if !ok || p.TextOffset != 0x80000 || p.PageSize() != "4K" || !p.PhysPlacement() || p.BigEndian() || !p.EFI {
		t.Fatalf("%+v %v", p, ok)
	}
	out := strings.Join(Describe(append(h, []byte(testBanner)...)), "\n")
	if !strings.Contains(out, "Form: AArch64 Image") || !strings.Contains(out, "4K pages") || !strings.Contains(out, "EFI stub") || !strings.Contains(out, "Kernel: Linux 3.18.24-tcc") {
		t.Errorf("%s", out)
	}
	if _, ok := ParseARM64(make([]byte, 0x40)); ok {
		t.Error("zeros are not an arm64 image")
	}
}
