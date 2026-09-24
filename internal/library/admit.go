package library

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/filetype"
	"go-unbrick/internal/secboot"
)

// Admission is the ingest verdict on a file offered as a loader. Scraped
// loader collections mix programmers with boot stages, whole boot-chain
// images, auth digests and patched builds, and all of them carry a signing
// chain — so a chain alone does not make a loader.
type Admission struct {
	// Programmer is the bytes to file: the input, or the programmer pulled out
	// of a container.
	Programmer []byte
	Extracted  string // record name the programmer came from, if unwrapped
	Reject     string // non-empty: why this is not a usable loader
	Class      string // short reject class, for tallies
}

// nonProgrammerTypes are signed image types (MBN v6+ metadata) confirmed to
// be boot-chain stages, never a programmer. See catalog/sw_ids.yaml.
var nonProgrammerTypes = map[uint32]string{
	0: "XBL/SBL1", 5: "DEVCFG", 7: "TZ", 10: "RPM", 12: "TZ app",
	21: "HYP", 28: "ABL", 36: "QUPFW", 37: "XBL_CONFIG",
}

var (
	reDigestName = regexp.MustCompile(`digest`)
	reStageName  = regexp.MustCompile(`(^|[_-])(sbl|xbl)[0-9]*([_.-]|$)`)
	// reBootImageName matches the well-known boot-chain image names — a
	// backstop for a test-signed image whose SW_ID is 0/absent.
	reBootImageName = regexp.MustCompile(`(?i)(^|[_/])(rpm|tz|tzbsp|hyp|keymaster|cmnlib|cmnlib64|widevine|playready|venus|wcnss|adsp|cdsp|slpi|sampleapp|devcfg|storsec|prov|prov64|aboot|appsboot|abl|uefi_sec|uefisecapp|xbl_config|xbl_sec|pmic|imagefv|multi_image|qupv3fw|dspso)([_.]|$)`)
)

// bootImageName reports whether base names a known boot-chain image.
func bootImageName(base string) bool { return reBootImageName.MatchString(base) }

// PruneAction is what Prune did, or would do, to one stored loader.
type PruneAction struct {
	Ref    LoaderRef
	Action string // "remove", "unwrap", "remove-duplicate"
	Why    string
	Class  string
}

// Prune applies Admit to every stored loader: rejected builds are removed,
// containers are replaced by the programmer inside them (or removed, when that
// programmer is already filed). With write false it only reports.
func (l *Library) Prune(write bool) ([]PruneAction, error) {
	var out []PruneAction
	for _, f := range l.Loaders() {
		builds := l.Builds(f)
		shas := map[string]bool{}
		for _, ref := range builds {
			shas[ref.Meta.SHA256] = true
		}
		for _, ref := range builds {
			blob, err := os.ReadFile(l.LoaderPath(ref))
			if err != nil {
				continue
			}
			a := Admit(blob, ref.Meta.Source)
			dir := l.buildDir(f, ref.Build)
			switch {
			case a.Reject != "":
				out = append(out, PruneAction{Ref: ref, Action: "remove", Why: a.Reject, Class: a.Class})
				if write {
					if err := os.RemoveAll(dir); err != nil {
						return out, err
					}
				}
			case a.Extracted != "":
				sum := sha256.Sum256(a.Programmer)
				sha := hex.EncodeToString(sum[:])
				if shas[sha] {
					out = append(out, PruneAction{Ref: ref, Action: "remove-duplicate", Class: "container",
						Why: a.Extracted + " inside is already filed"})
					if write {
						if err := os.RemoveAll(dir); err != nil {
							return out, err
						}
					}
					continue
				}
				shas[sha] = true
				out = append(out, PruneAction{Ref: ref, Action: "unwrap", Class: "container",
					Why: "replaced by its " + a.Extracted})
				if !write {
					continue
				}
				m := ref.Meta
				m.SHA256 = sha
				if id, err := secboot.FromImage(a.Programmer); err == nil {
					m.OEMID, m.HWID, m.JTAGID, m.SWID, m.Root = id.OEMID, id.HWID, id.JTAGID, id.SWID, id.Root
				}
				if err := writeFile(filepath.Join(dir, "programmer.elf"), a.Programmer); err != nil {
					return out, err
				}
				if err := writeJSON(filepath.Join(dir, "meta.json"), m); err != nil {
					return out, err
				}
			}
		}
	}
	return out, nil
}

// Admit decides whether blob, filed from a file called name, is a loader.
func Admit(blob []byte, name string) Admission {
	base := strings.ToLower(filepath.Base(name))
	a := Admission{Programmer: blob}
	reject := func(class, why string, args ...any) Admission {
		a.Class, a.Reject = class, fmt.Sprintf(why, args...)
		return a
	}
	if reDigestName.MatchString(base) {
		return reject("digest", "auth digest, not a loader")
	}
	switch filetype.Detect(blob) {
	case filetype.SingleNLonely:
		// Motorola's singleimage.bin: the whole boot chain plus the programmer.
		recs, err := blankflash.Parse(blob)
		if err != nil {
			return reject("container", "unreadable SINGLE_N_LONELY container")
		}
		for _, r := range recs {
			if strings.HasPrefix(strings.ToLower(r.Name), "programmer.") {
				a.Programmer, a.Extracted = r.Data, r.Name
				break
			}
		}
		if a.Extracted == "" {
			return reject("container", "SINGLE_N_LONELY container with no programmer record")
		}
	case filetype.GPT:
		return reject("container", "raw disk image (GPT + boot partitions), not a loader")
	}
	id, err := secboot.FromImage(a.Programmer)
	if err != nil {
		return reject("unsigned", "no signing identity: %v", err)
	}
	if id.MultiImage > 1 {
		return reject("container", "boot-chain image (%d signed stages), not a loader", id.MultiImage)
	}
	// The image type identifies a boot-chain stage. SW_ID stage 0 is excluded:
	// it is "unset" on many genuine programmers, not XBL. Both the v6 metadata
	// and the leaf cert carry the SW_ID (test-signed boot images have no
	// metadata but a cert stage), so a non-zero one is checked either way.
	if sw := id.SWType(); sw != 0 {
		if stage, ok := nonProgrammerTypes[sw]; ok {
			return reject("stage", "signed as %s (SW_ID %d), not a programmer", stage, sw)
		}
	} else if reStageName.MatchString(base) {
		return reject("stage", "boot stage (sbl/xbl), not a programmer")
	}
	// A signed image that carries none of the firehose protocol vocabulary and
	// is not a streaming loader is not a programmer at all — a boot-chain image
	// (rpm/tz/keymaster/venus/…) misfiled by its source name. Compressed
	// firehose loaders are rare; the SW_ID and name checks above catch the ones
	// that are genuinely boot images, so this only fires when nothing else can
	// vouch for it.
	if secboot.ScanPeek(a.Programmer) == secboot.PeekUnknown && bootImageName(base) {
		return reject("stage", "boot-chain image (%s), not a firehose programmer", base)
	}
	if in := secboot.VerifySegments(a.Programmer); in.Patched() {
		return reject("patched", "patched: code segment(s) %v differ from the signed hash table", in.CodeBad)
	}
	return a
}
