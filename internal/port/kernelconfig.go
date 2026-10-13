package port

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The stock kernel carries its own build configuration when it was built with
// IKCONFIG: a gzip stream between "IKCFG_ST" and "IKCFG_ED" in the image. It
// settles what a module list cannot: a driver with no .ko is built in (=y) or
// not built at all.

// KernelImage is the kernel as the boot image holds it, inflated when it is a
// gzip file (arm64 images usually are not, but some vendors ship Image.gz).
func KernelImage(b []byte) []byte {
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		if zr, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
			if out, err := io.ReadAll(zr); err == nil || len(out) > 0 {
				return out
			}
		}
	}
	return b
}

// KernelConfig is the stock kernel's configuration: symbol (with CONFIG_) to
// its value, "n" for one the file says is not set. nil when the kernel does not
// embed one.
func KernelConfig(kernel []byte) map[string]string {
	i := bytes.Index(kernel, []byte("IKCFG_ST"))
	if i < 0 {
		return nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(kernel[i+len("IKCFG_ST"):]))
	if err != nil {
		return nil
	}
	text, _ := io.ReadAll(zr) // trailing bytes after the stream are not an error here
	cfg := map[string]string{}
	for _, line := range strings.Split(string(text), "\n") {
		switch {
		case strings.HasPrefix(line, "CONFIG_"):
			if k, v, ok := strings.Cut(line, "="); ok {
				cfg[k] = strings.Trim(v, `"`)
			}
		case strings.HasPrefix(line, "# CONFIG_") && strings.HasSuffix(line, " is not set"):
			cfg[strings.TrimSuffix(strings.TrimPrefix(line, "# "), " is not set")] = "n"
		}
	}
	if len(cfg) == 0 {
		return nil
	}
	return cfg
}

// ConfigText is the configuration in file form, for the bundle.
func ConfigText(cfg map[string]string) string {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		switch v := cfg[k]; {
		case v == "n":
			fmt.Fprintf(&b, "# %s is not set\n", k)
		case v == "y" || v == "m" || isNumber(v):
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		default:
			fmt.Fprintf(&b, "%s=%q\n", k, v)
		}
	}
	return b.String()
}

func isNumber(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// ConfigEvidence is what the stock config says about a part's driver, by name:
// the enabled symbols (=y or =m) that carry the compatible's vendor and one of
// its other words, else the disabled ones. A compatible does not name its
// Kconfig symbol, so this is a name match to confirm by hand, not a binding.
// It returns nothing when there is no config or nothing matches.
func (p Package) ConfigEvidence(compatible string) (enabled, disabled []string, vendorOnly bool) {
	// Only a "<vendor>,<part>" compatible names a vendor; "simple-battery" and
	// "fixed-factor-clock" are generic bindings whose first word means nothing.
	// qcom is the vendor of too much of the config to say anything.
	if p.KernelConfig == nil || !strings.Contains(compatible, ",") || strings.HasPrefix(compatible, "qcom,") {
		return nil, nil, false
	}
	words := compatibleWords(compatible)
	if len(words) == 0 {
		return nil, nil, false
	}
	vendor, rest := words[0], words[1:]
	pick := func(match func(name string) bool) (en, dis []string) {
		for sym, v := range p.KernelConfig {
			if !match(strings.ToLower(sym)) {
				continue
			}
			if v == "n" {
				dis = append(dis, sym+"=n")
			} else {
				en = append(en, sym+"="+v)
			}
		}
		sort.Strings(en)
		sort.Strings(dis)
		return en, dis
	}
	enabled, disabled = pick(func(n string) bool { return strings.Contains(n, vendor) && containsAny(n, rest) })
	if len(enabled)+len(disabled) > 0 {
		return enabled, disabled, false
	}
	// The product word often is not the symbol's ("hxcommon" for HIMAX_COMMON):
	// fall back to the vendor alone, but only for a vendor with few symbols, since
	// "qcom" names hundreds and says nothing.
	en, dis := pick(func(n string) bool { return strings.Contains(n, vendor) })
	// A disabled symbol of the same vendor says nothing about this part.
	if len(en) > 0 && len(en)+len(dis) <= maxVendorSymbols {
		return en, nil, true
	}
	return nil, nil, false
}

// maxVendorSymbols bounds a vendor-only match: past it the vendor is too broad
// for its symbols to be evidence about one part.
const maxVendorSymbols = 24

// compatibleWords splits "novatek,NVT-ts-spi" into lower-case words long enough
// to mean something, vendor first.
func compatibleWords(c string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(c), func(r rune) bool {
		return r == ',' || r == '-' || r == '_' || r == '.' || r == ' '
	}) {
		if len(w) >= 3 && w != "i2c" && w != "spi" {
			out = append(out, w)
		}
	}
	return out
}

func containsAny(s string, words []string) bool {
	if len(words) == 0 {
		return true
	}
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// configVerdict says, for a part no module binds, what the stock config
// suggests: built in, built out, or no matching symbol.
func configVerdict(p Package, compatible string) string {
	en, dis, weak := p.ConfigEvidence(compatible)
	how := "by name"
	if weak {
		how = "same vendor only"
	}
	switch {
	case len(en) > 0:
		return "(no module; stock config, " + how + ": " + joinMax(en, 3) + ")"
	case len(dis) > 0:
		return "(no module; stock config, " + how + ": " + joinMax(dis, 3) + ")"
	}
	return "(no module; no stock config symbol matches by name)"
}

func joinMax(s []string, n int) string {
	if len(s) > n {
		return strings.Join(s[:n], ", ") + fmt.Sprintf(" (+%d)", len(s)-n)
	}
	return strings.Join(s, ", ")
}
