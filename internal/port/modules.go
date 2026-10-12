package port

import (
	"bytes"
	"debug/elf"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Module is what a kernel module (.ko) says about itself: enough to say which
// device-tree compatible it binds and which firmware files it names, with no
// table of drivers.
type Module struct {
	Name        string // "chipone_tddi_v2_mmi"
	Description string
	Depends     []string
	Aliases     []string // "of:N*T*Cchipone-tddi", "i2c:aw882xx_smartpa"
	// Firmware are file names the module names: its MODULE_FIRMWARE entries and
	// any string in it shaped like a firmware file name. A name a driver builds
	// at run time (a%d_zap) is not here.
	Firmware []string
}

// firmwareName is a string shaped like a firmware file name.
var firmwareName = regexp.MustCompile(`[A-Za-z0-9_][A-Za-z0-9_.\-]{2,60}\.(?:bin|fw|mbn|mdt|elf|tlv|hex|ini|csv|img|jsn)\b`)

// ReadModule reads a module's identity from its bytes. name is the file name.
func ReadModule(name string, b []byte) Module {
	m := Module{Name: strings.TrimSuffix(path.Base(name), ".ko")}
	seen := map[string]bool{}
	add := func(f string) {
		if !seen[f] {
			seen[f] = true
			m.Firmware = append(m.Firmware, f)
		}
	}
	if f, err := elf.NewFile(bytes.NewReader(b)); err == nil {
		if s := f.Section(".modinfo"); s != nil {
			if data, err := s.Data(); err == nil {
				for _, kv := range parseModinfo(data) {
					switch kv[0] {
					case "description":
						m.Description = kv[1]
					case "depends":
						if kv[1] != "" {
							m.Depends = strings.Split(kv[1], ",")
						}
					case "alias":
						m.Aliases = append(m.Aliases, kv[1])
					case "firmware":
						add(kv[1])
					}
				}
			}
		}
	}
	for _, s := range firmwareName.FindAll(b, -1) {
		add(string(s))
	}
	sort.Strings(m.Firmware)
	return m
}

// parseModinfo splits a .modinfo section (NUL-separated key=value) into pairs.
func parseModinfo(data []byte) [][2]string {
	var out [][2]string
	for _, e := range bytes.Split(data, []byte{0}) {
		if k, v, ok := strings.Cut(string(e), "="); ok && k != "" {
			out = append(out, [2]string{k, v})
		}
	}
	return out
}

// Binding finds the module that binds a device-tree node: by an of: alias for
// its compatible, or, for an I2C or SPI device, the bus alias the kernel
// derives from the compatible by dropping its vendor prefix.
func Binding(mods []Module, compatible string) (Module, bool) {
	prefixes := []string{"of:N*T*C" + compatible}
	if _, dev, ok := strings.Cut(compatible, ","); ok {
		prefixes = append(prefixes, "i2c:"+dev, "spi:"+dev)
	}
	for _, m := range mods {
		for _, a := range m.Aliases {
			for _, p := range prefixes {
				// "...Cname" and "...CnameC*" (a compatible list) both match.
				if a == p || strings.HasPrefix(a, p+"C") {
					return m, true
				}
			}
		}
	}
	return Module{}, false
}
