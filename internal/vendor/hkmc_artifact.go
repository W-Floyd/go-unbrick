package vendor

// Content recognition for the Hyundai/Kia head-unit package's own formats and
// the supplier firmware it carries (Trimble GPS, Micron FFU).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/npkg"
)

func hkmcArtifact(name string, data []byte) (ArtifactInfo, bool) {
	switch {
	case bytes.HasPrefix(data, []byte("ConB")) && len(data) >= 0x28:
		info := ArtifactInfo{Label: "navi config (ConB)"}
		if n := utf16Name(data[0x28:]); n != "" {
			info.Detail = n
		}
		return info, true
	case npkg.Is(data):
		// No Detail: ArtifactReport below prints the validated Summary and the
		// section table, so a short teaser here would just repeat its first line.
		return ArtifactInfo{Label: "navi package (PRNM)"}, true
	case bytes.HasPrefix(data, []byte(splashMagic)):
		info := ArtifactInfo{Label: "splash container"}
		if imgs, err := ParseSplash(data); err == nil {
			info.Detail = fmt.Sprintf("%d images", len(imgs))
		}
		return info, true
	case filepath.Base(name) == "micom_sw.bin":
		return ArtifactInfo{Label: "micom firmware"}, true
	case bytes.HasPrefix(data, []byte("TRMB")):
		return ArtifactInfo{Label: "Trimble GPS firmware (TRMB)"}, true
	case filepath.Base(name) == "ffu_sw.bin" && len(data) >= 0x28 && bytes.Contains(data[0x20:0x28], []byte("QT00R")):
		// The tag's first byte varies (seen "F" on a 64 GB part, "9" on a 128 GB
		// part; likely a capacity/revision code, not a fixed vendor magic), so the
		// match keys on the stable "QT00R" run rather than anchoring at the start.
		return ArtifactInfo{Label: "Micron FFU firmware", Detail: string(bytes.TrimRight(data[0x20:0x28], "\x00"))}, true
	case looksLikeTarList(data):
		info := ArtifactInfo{Label: "TarList manifest (XOR 0x11)"}
		if m := tarListVersionRe.FindSubmatch(DecodeTarList(data)); m != nil {
			info.Detail = string(m[1])
		}
		return info, true
	case bytes.HasPrefix(data, []byte("SWVERSION")):
		info := ArtifactInfo{Label: "update.info manifest"}
		if v := ParseUpdateInfo(data); v != "" {
			info.Detail = v
		}
		return info, true
	case strings.HasSuffix(filepath.Base(name), "_encrypted.rsa") && isRSASigLen(len(data)):
		return ArtifactInfo{Label: fmt.Sprintf("RSA-%d signature (TarList)", len(data)*8)}, true
	}
	if n := jsonWithRSATrailerLen(data); n > 0 {
		return ArtifactInfo{Label: fmt.Sprintf("JSON manifest + appended RSA-%d signature", n*8)}, true
	}
	return ArtifactInfo{}, false
}

var tarListVersionRe = regexp.MustCompile(`@NEW_VERSION:(\S+)`)

// isRSASigLen reports a plausible raw RSA signature length (modulus size in
// bytes, for a common key size); not a parse, just a sanity bound so a file
// that merely shares the ".rsa" suffix convention by coincidence isn't
// mislabeled.
func isRSASigLen(n int) bool {
	switch n {
	case 128, 256, 384, 512: // RSA-1024, -2048, -3072, -4096
		return true
	}
	return false
}

// jsonWithRSATrailerLen reports the length of a raw RSA signature appended
// directly after a JSON document, with no separator, or 0 when data isn't
// shaped like one: trimming a plausible signature length off the end must
// leave exactly one complete, valid JSON value (MAINCONFIG_G1.json's update
// notice is signed this way, unlike update.info/TarList, whose signature is
// a sibling file instead - see hkmcArtifact's "_encrypted.rsa" case).
func jsonWithRSATrailerLen(data []byte) int {
	for _, n := range [...]int{512, 384, 256, 128} {
		if len(data) <= n {
			continue
		}
		if json.Valid(data[:len(data)-n]) {
			return n
		}
	}
	return 0
}

// looksLikeTarList checks only the first few bytes (decoded) for one of
// NEW_TarList.txt_encrypted's record markers, so it's cheap to run against
// every file recon sees and works even on a head-only sample of a large one.
func looksLikeTarList(data []byte) bool {
	n := min(len(data), 32)
	if n == 0 {
		return false
	}
	dec := DecodeTarList(data[:n])
	for _, p := range [...]string{"@FILE:", "@VERSION:", "@NEW_VERSION:", "@SWVERSION", "@NEW_SWVERSION"} {
		if bytes.HasPrefix(dec, []byte(p)) {
			return true
		}
	}
	return false
}

// utf16Name reads the first NUL-terminated UTF-16LE ASCII string of b, which
// begins with a 4-byte length field before the text in ConB records.
func utf16Name(b []byte) string {
	var out []byte
	for i := 0; i+1 < len(b) && len(out) < 64; i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			break
		}
		if b[i+1] != 0 || b[i] < 0x20 || b[i] > 0x7e {
			return ""
		}
		out = append(out, b[i])
	}
	return string(out)
}

// ArtifactReport implements ArtifactReporter: a PRNM package's section table
// (full validation needs the whole file, which head alone may not cover).
func (hkmc) ArtifactReport(path string, head []byte) []string {
	if !npkg.Is(head) {
		return nil
	}
	data, err := infile.ReadFile(path)
	if err != nil {
		return nil
	}
	p, err := npkg.Parse(data, int64(len(data)))
	if err != nil {
		return []string{fmt.Sprintf("PRNM header doesn't check out: %v", err)}
	}
	return p.Report()
}
