package telechips

import (
	"regexp"
	"strings"
)

var configRe = regexp.MustCompile(`(?m)^(CONFIG_[A-Z0-9_]+)=(.*?)\s*$`)

// ParseDefconfig reads a U-Boot defconfig: the CONFIG_ symbols it sets and
// their values (comments and unset symbols are not in it).
func ParseDefconfig(data []byte) map[string]string {
	out := map[string]string{}
	for _, m := range configRe.FindAllSubmatch(data, -1) {
		out[string(m[1])] = strings.Trim(string(m[2]), `"`)
	}
	return out
}

// ubootFeatures are the symbols that say what a U-Boot build can do for
// recovery and image trust, in the order they are reported.
var ubootFeatures = []struct{ sym, words string }{
	{"CONFIG_FIT_SIGNATURE", "FIT image signatures"},
	{"CONFIG_RSA", "RSA verification"},
	{"CONFIG_USB_FUNCTION_FASTBOOT", "USB fastboot"},
	{"CONFIG_CMD_USB", "USB commands"},
	{"CONFIG_USB_STORAGE", "USB storage"},
	{"CONFIG_CMD_FASTBOOT", "fastboot command"},
	{"CONFIG_CMD_GPT", "GPT command"},
	{"CONFIG_SPL_FIT_SIGNATURE", "SPL FIT signatures"},
}

// DescribeUBoot is the recovery and image-trust features a defconfig turns on.
func DescribeUBoot(cfg map[string]string) []string {
	var out []string
	for _, f := range ubootFeatures {
		if v, ok := cfg[f.sym]; ok && v == "y" {
			out = append(out, f.words)
		}
	}
	return out
}
