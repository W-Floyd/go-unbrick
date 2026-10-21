package bootimg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// What a Linux kernel says about itself, whichever form it is in: an AArch64
// "Image" (a header with its own magic), an ARM zImage (a decompressor stub around
// a compressed kernel), or the raw ARM Image that stub unpacks to (no header at
// all, found by the banner every kernel carries).

// ARM64Header is the 64-byte header of an AArch64 Image (the kernel's
// Documentation/arm64/booting.rst).
type ARM64Header struct {
	TextOffset uint64
	ImageSize  uint64 // including bss, so more than the file
	Flags      uint64
	EFI        bool // a PE/COFF header follows ("MZ" at 0): it boots as an EFI application too
	PEOffset   uint32
}

// BigEndian says the kernel is built big-endian.
func (h ARM64Header) BigEndian() bool { return h.Flags&1 != 0 }

// PageSize is the kernel's page size: "4K", "16K", "64K", or "" when unstated.
func (h ARM64Header) PageSize() string {
	return [...]string{"", "4K", "16K", "64K"}[(h.Flags>>1)&3]
}

// PhysPlacement says the kernel may be placed anywhere in memory (not just near
// the start of RAM).
func (h ARM64Header) PhysPlacement() bool { return h.Flags&(1<<3) != 0 }

// ParseARM64 reads an AArch64 Image header.
func ParseARM64(head []byte) (*ARM64Header, bool) {
	if !IsAArch64Image(head) || len(head) < 0x40 {
		return nil, false
	}
	le := binary.LittleEndian
	return &ARM64Header{
		TextOffset: le.Uint64(head[8:]), ImageSize: le.Uint64(head[16:]), Flags: le.Uint64(head[24:]),
		EFI: bytes.HasPrefix(head, []byte("MZ")), PEOffset: le.Uint32(head[0x3c:]),
	}, true
}

// ZImageHeader is what an ARM zImage records of itself at 0x24.
type ZImageHeader struct {
	Start, End uint32 // where the zImage is, relative to its own start, and where it ends
}

// ParseZImage reads an ARM zImage's header.
func ParseZImage(head []byte) (*ZImageHeader, bool) {
	if !IsZImage(head) || len(head) < 0x30 {
		return nil, false
	}
	le := binary.LittleEndian
	return &ZImageHeader{Start: le.Uint32(head[0x28:]), End: le.Uint32(head[0x2c:])}, true
}

// ZImageCompression names what a zImage's payload is compressed with, from the first
// bytes of the stream, and where it starts. "" when none is found.
func ZImageCompression(z []byte) (name string, off int) {
	for _, c := range []struct {
		magic []byte
		name  string
	}{
		{[]byte{0x1f, 0x8b, 0x08}, "gzip"},
		{[]byte{0xfd, '7', 'z', 'X', 'Z', 0}, "xz"},
		{[]byte{0x5d, 0x00, 0x00, 0x80, 0x00}, "lzma"},
		{[]byte{0x02, 0x21, 0x4c, 0x18}, "lz4"},
		{[]byte{0x89, 'L', 'Z', 'O', 0}, "lzo"},
	} {
		if i := bytes.Index(z, c.magic); i >= 0 && (off == 0 || i < off) {
			name, off = c.name, i
		}
	}
	return name, off
}

// Banner is the version line every kernel carries ("Linux version 3.18.24-tcc
// (builder@host) (gcc version 4.7 (GCC) ) #1 SMP PREEMPT Thu May 7 ...").
type Banner struct {
	Release  string // 3.18.24-tcc
	Builder  string // user@host
	Compiler string
	Build    string // "#1 SMP PREEMPT Thu May 7 09:25:08 KST 2026"
}

var bannerRE = regexp.MustCompile(`Linux version (\S+) \(([^)]*)\) \((.*?)\) (#[^\n\x00]*)`)

// FindBanner finds the kernel's version banner in an image, if it has one.
func FindBanner(kernel []byte) (Banner, bool) {
	for off := 0; ; {
		i := bytes.Index(kernel[off:], []byte("Linux version "))
		if i < 0 {
			return Banner{}, false
		}
		end := min(off+i+1024, len(kernel))
		if m := bannerRE.FindSubmatch(kernel[off+i : end]); m != nil {
			return Banner{Release: string(m[1]), Builder: string(m[2]), Compiler: strings.TrimSpace(string(m[3])), Build: strings.TrimSpace(string(m[4]))}, true
		}
		off += i + 1
	}
}

// ConfigHighlights summarises a kernel .config: the architecture it is built for,
// how it is compressed, and what it has for and against it on the security side.
// Each line is one fact; nothing is guessed from what is absent beyond "not set".
func ConfigHighlights(cfg []byte) []string {
	set := map[string]string{}
	for _, line := range strings.Split(string(cfg), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.HasPrefix(k, "CONFIG_") {
			set[strings.TrimPrefix(k, "CONFIG_")] = strings.Trim(v, `"`)
		}
	}
	on := func(k string) bool { return set[k] == "y" }
	var arch []string
	for _, k := range []string{"ARM64", "ARM", "CPU_V7", "ARM_LPAE", "ARM_APPENDED_DTB", "SMP", "PREEMPT", "ARM_PSCI"} {
		if on(k) {
			arch = append(arch, k)
		}
	}
	for k := range set {
		if strings.HasPrefix(k, "ARCH_TCC") || strings.HasPrefix(k, "MACH_") && set[k] == "y" {
			arch = append(arch, k)
		}
	}
	sort.Strings(arch)
	var out []string
	if len(arch) > 0 {
		out = append(out, "built for: "+strings.Join(arch, ", "))
	}
	for _, k := range []string{"KERNEL_GZIP", "KERNEL_XZ", "KERNEL_LZMA", "KERNEL_LZO", "KERNEL_LZ4"} {
		if on(k) {
			out = append(out, "compression: "+strings.ToLower(strings.TrimPrefix(k, "KERNEL_")))
		}
	}
	if v := set["LOCALVERSION"]; v != "" {
		out = append(out, "localversion: "+v)
	}
	if v := strings.TrimSpace(set["CMDLINE"]); v != "" {
		out = append(out, "built-in command line: "+v)
	}
	var yes, no []string
	for _, f := range []struct{ key, name string }{
		{"SECURITY_SELINUX", "SELinux"}, {"DEFAULT_SECURITY_SELINUX", "SELinux default"}, {"DM_VERITY", "dm-verity"},
		{"DM_CRYPT", "dm-crypt"}, {"CC_STACKPROTECTOR_STRONG", "stack protector (strong)"}, {"MODULE_SIG", "module signing"},
		{"SECCOMP", "seccomp"}, {"STRICT_DEVMEM", "strict /dev/mem"}, {"AUDIT", "audit"}, {"OPTEE", "OP-TEE"},
	} {
		if on(f.key) {
			yes = append(yes, f.name)
		} else {
			no = append(no, f.name)
		}
	}
	if len(yes) > 0 {
		out = append(out, "on: "+strings.Join(yes, ", "))
	}
	if len(no) > 0 {
		out = append(out, "not set: "+strings.Join(no, ", "))
	}
	var open []string
	for _, f := range []struct{ key, name string }{
		{"DEVMEM", "/dev/mem"}, {"DEVKMEM", "/dev/kmem"}, {"KALLSYMS_ALL", "all kallsyms"}, {"KEXEC", "kexec"},
		{"MAGIC_SYSRQ", "sysrq"}, {"DEBUG_FS", "debugfs"}, {"FTRACE", "ftrace"}, {"USB_G_ANDROID", "Android USB gadget"},
	} {
		if on(f.key) {
			open = append(open, f.name)
		}
	}
	if len(open) > 0 {
		out = append(out, "present: "+strings.Join(open, ", "))
	}
	return out
}

// Describe is a kernel file's lines for a report: the banner, the form it is in
// (and what a zImage unpacks to), and its configuration when it embeds one.
func Describe(file []byte) []string {
	var out []string
	kernel := file
	switch {
	case IsZImage(file):
		z, _ := ParseZImage(file)
		comp, off := ZImageCompression(file)
		line := fmt.Sprintf("Form: ARM zImage, %s, payload (%s) at 0x%x", kib(len(file)), orNone(comp), off)
		if z != nil && z.End != uint32(len(file)) {
			line += fmt.Sprintf("; header says it ends at 0x%x of %d (data after it: an appended device tree?)", z.End, len(file))
		}
		out = append(out, line)
		if plain, err := ZImagePayload(file); err == nil {
			out = append(out, fmt.Sprintf("  unpacks to %s", kib(len(plain))))
			kernel = plain
		} else {
			out = append(out, "  payload not unpacked: "+err.Error())
			kernel = nil
		}
	case IsAArch64Image(file):
		h, _ := ParseARM64(file)
		line := fmt.Sprintf("Form: AArch64 Image, %s, text offset 0x%x, image size %s with bss", kib(len(file)), h.TextOffset, kib(int(h.ImageSize)))
		if ps := h.PageSize(); ps != "" {
			line += ", " + ps + " pages"
		}
		if h.BigEndian() {
			line += ", big-endian"
		}
		if h.EFI {
			line += ", EFI stub"
		}
		out = append(out, line)
	default:
		out = append(out, fmt.Sprintf("Form: raw kernel image (no header), %s", kib(len(file))))
	}
	if b, ok := FindBanner(kernel); ok {
		out = append([]string{"Kernel: Linux " + b.Release, "  built by " + b.Builder + ", " + b.Compiler, "  " + b.Build}, out...)
	}
	if fs, ok := BuiltinInitramfs(kernel); ok {
		switch {
		case fs.Default():
			out = append(out, "Initramfs: built in, the empty default (/dev/console, /root): the root filesystem comes from elsewhere, named by the boot arguments")
		default:
			out = append(out, fmt.Sprintf("Initramfs: built in, %d entries, %s of files", len(fs.Entries)-1, kib(fs.Bytes)))
		}
	} else if kernel != nil {
		out = append(out, "Initramfs: none built in")
	}
	if cfg, ok := KernelConfig(kernel); ok {
		out = append(out, fmt.Sprintf("Config: embedded (IKCONFIG), %s", kib(len(cfg))))
		for _, l := range ConfigHighlights(cfg) {
			out = append(out, "  "+l)
		}
	}
	return out
}

func kib(n int) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%.1f KiB", float64(n)/1024)
}

func orNone(s string) string {
	if s == "" {
		return "no known compressor"
	}
	return s
}

// StartsLikeARMKernel says the first word is what a raw 32-bit ARM kernel starts
// with: an ARM-mode branch (B or BL, always) or the no-operation MOV r0, r0. It
// proves nothing alone, since any ARM firmware starts so; it is the cheap test that
// says whether the file is worth reading in full for the rest of IsRawKernel.
func StartsLikeARMKernel(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	w := binary.LittleEndian.Uint32(head)
	return w>>24 == 0xea || w>>24 == 0xeb || w == 0xe1a00000
}

// kernelMessages are text only a kernel carries, which a file that merely mentions
// the version banner (a log, a documentation page) does not.
var kernelMessages = [][]byte{
	[]byte("Kernel panic - not syncing"),
	[]byte("Unable to mount root fs"),
	[]byte("No working init found"),
	[]byte("Freeing unused kernel memory"),
}

// IsRawKernel says data is a Linux kernel with no header: the raw image an ARM
// zImage unpacks to, or one built uncompressed. Nothing at its start names it, so it
// is known by what it starts with (ARM code), its version banner, and a message that
// only a kernel contains.
func IsRawKernel(data []byte) bool {
	if !StartsLikeARMKernel(data) {
		return false
	}
	if _, ok := FindBanner(data); !ok {
		return false
	}
	for _, m := range kernelMessages {
		if bytes.Contains(data, m) {
			return true
		}
	}
	return false
}

// Initramfs is what a kernel carries as its built-in initial root filesystem: a
// cpio archive linked into the image.
type Initramfs struct {
	Offset  int
	Entries []string // member names, in archive order
	Bytes   int      // the files' contents together
}

// Default says it is the empty one the kernel build makes when given no root
// filesystem to embed (a /dev/console node and a /root directory), so the real root
// comes from elsewhere: the boot arguments name it.
func (r Initramfs) Default() bool {
	if len(r.Entries) > 4 || r.Bytes != 0 {
		return false
	}
	for _, n := range r.Entries {
		if n != "dev" && n != "dev/console" && n != "root" && n != "TRAILER!!!" {
			return false
		}
	}
	return len(r.Entries) > 0
}

// BuiltinInitramfs finds the largest complete cpio (newc) archive in a kernel: the
// built-in initramfs. A kernel may well have none.
func BuiltinInitramfs(kernel []byte) (Initramfs, bool) {
	var best Initramfs
	found := false
	for off := 0; ; {
		i := bytes.Index(kernel[off:], []byte("070701"))
		if i < 0 {
			break
		}
		start := off + i
		off = start + 1
		r, ok := walkCpio(kernel, start)
		if ok && (!found || len(r.Entries) > len(best.Entries)) {
			best, found = r, true
		}
	}
	return best, found
}

// walkCpio reads a newc archive from start through its TRAILER!!!; ok is false if
// anything on the way is not one.
func walkCpio(d []byte, start int) (Initramfs, bool) {
	r := Initramfs{Offset: start}
	hex := func(b []byte) (int, bool) {
		n := 0
		for _, c := range b {
			switch {
			case c >= '0' && c <= '9':
				n = n<<4 | int(c-'0')
			case c >= 'a' && c <= 'f':
				n = n<<4 | int(c-'a'+10)
			case c >= 'A' && c <= 'F':
				n = n<<4 | int(c-'A'+10)
			default:
				return 0, false
			}
		}
		return n, true
	}
	// Padding is to four bytes from the start of the archive, not of the file.
	align := func(n int) int { return start + (n-start+3)&^3 }
	off := start
	for len(r.Entries) < 1<<16 {
		if off+110 > len(d) || string(d[off:off+6]) != "070701" {
			return r, false
		}
		size, ok1 := hex(d[off+54 : off+62])
		namesz, ok2 := hex(d[off+94 : off+102])
		if !ok1 || !ok2 || namesz < 1 || namesz > 4096 || off+110+namesz > len(d) {
			return r, false
		}
		name := string(d[off+110 : off+110+namesz-1])
		r.Entries = append(r.Entries, name)
		body := align(off + 110 + namesz)
		if name == "TRAILER!!!" {
			return r, true
		}
		r.Bytes += size
		off = align(body + size)
	}
	return r, false
}
