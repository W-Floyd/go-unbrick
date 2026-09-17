package blankflash

// Harvest the target device's own bootloader partitions and GPT.
//
// These come from the target's *own* stock firmware -- never the donor's --
// because only the loader is cross-device; the partitions and partition table are
// unique to the target model (and, for the GPT, to the target unit's storage). Two
// sources are supported: the packed bootloader.img from a stock package, or a
// directory of raw per-partition dumps (e.g. xbl_a.img pulled off the live
// device), which is the most faithful source for a specific unit.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// defaultMapOrder / defaultMap: recipe partition label -> the filename qboot
// expects inside the singleimage. Derived from Motorola stock
// bootloader.default.xml; the tool prefers the target's own map when present and
// falls back to this. Order matters for deterministic dump scanning.
var defaultMapOrder = []string{
	"abl", "xbl", "xbl_config", "qupfw", "rpm", "tz",
	"hyp", "devcfg", "keymaster", "storsec", "prov", "uefisecapp",
}

var defaultMap = map[string]string{
	"abl":        "abl.elf",
	"xbl":        "xbl.elf",
	"xbl_config": "xbl_config.elf",
	"qupfw":      "qupfw.elf",
	"rpm":        "rpm.mbn",
	"tz":         "tz.mbn",
	"hyp":        "hyp.mbn",
	"devcfg":     "devcfg.mbn",
	"keymaster":  "keymaster.mbn",
	"storsec":    "storsec.mbn",
	"prov":       "prov64.mbn",
	"uefisecapp": "uefi_sec.mbn",
}

type Target struct {
	Parts    map[string][]byte // filename (as flashed) -> bytes
	FlashMap map[string]string // partition label -> filename
	// FlashOrder is the order the device's own recipe flashes those labels in.
	// The set matters as much as the order: a fixed list omits whatever a given
	// SoC adds (aop, cmnlib, cpucp, shrm, spss...), and a forged package that
	// skips them does not flash firmware the genuine one does.
	FlashOrder []string
	GPT        []byte // gpt.bin (kept whole; qboot flashes it as-is)
	Storage    string // emmc / ufs, if determinable
	Source     string
	// CID is the carrier/subsidy channel the package declares it targets, in the
	// hex spelling both flashfile.xml and `fastboot getvar cid` use ("0x0032").
	// The bootloader refuses a package whose CID does not match the device's, so
	// this — not the filename's build id — says which units will accept it.
	CID string
	// SubsidyLock is the subsidy-lock config the package carries
	// ("slcf_rev_d_ccaws_v5.0.nvm"); it names the channel the CID is a number for.
	SubsidyLock string
}

var (
	rePartFile = regexp.MustCompile(`partition="([^"]+)"\s+filename="([^"]+)"`)
	reSlot     = regexp.MustCompile(`_[ab]$`)
	reGPTMain  = regexp.MustCompile(`^gpt_main\d+\.bin$`)
)

func flashMapFromRecipe(recipeXML []byte) (map[string]string, []string) {
	txt := string(recipeXML)
	out := map[string]string{}
	var order []string
	for _, m := range rePartFile.FindAllStringSubmatch(txt, -1) {
		label, fn := m[1], m[2]
		if label == "partition" { // the GPT pseudo-target
			continue
		}
		label = reSlot.ReplaceAllString(label, "")
		if _, seen := out[label]; !seen {
			order = append(order, label)
		}
		out[label] = fn
	}
	return out, order
}

func inferStorage(gpt, recipeXML []byte) string {
	if len(recipeXML) > 0 {
		if m := reStore.FindStringSubmatch(string(recipeXML)); m != nil {
			return strings.ToLower(m[1])
		}
	}
	if gpt != nil && IsContainer(gpt) {
		if recs, err := Parse(gpt); err == nil {
			luns := 0
			for n := range Index(recs) {
				if reGPTMain.MatchString(n) {
					luns++
				}
			}
			// >1 LUN GPT is a UFS trait; a single main GPT is typical of eMMC.
			if luns > 1 {
				return "ufs"
			}
			return "emmc"
		}
	}
	return ""
}

func FromBootloaderImg(img, gpt []byte) (*Target, error) {
	recs, err := Parse(img)
	if err != nil {
		return nil, err
	}
	idx := Index(recs)
	var recipe []byte
	for n, v := range idx {
		if strings.HasSuffix(n, "default.xml") {
			recipe = v
			break
		}
	}
	flashMap, flashOrder := flashMapFromRecipe(recipe)
	if len(flashMap) == 0 {
		flashMap = map[string]string{}
		for k, v := range defaultMap {
			flashMap[k] = v
		}
	}
	parts := map[string][]byte{}
	for _, fn := range flashMap {
		if v, ok := idx[fn]; ok {
			parts[fn] = v
		}
	}
	return &Target{
		Parts:      parts,
		FlashMap:   flashMap,
		FlashOrder: flashOrder,
		GPT:        gpt,
		Storage:    inferStorage(gpt, recipe),
		Source:     "bootloader.img",
	}, nil
}

// FromDumps builds a target from raw per-partition dumps like xbl_a.img.
func FromDumps(dumpDir, slot string, gpt []byte) (*Target, error) {
	parts := map[string][]byte{}
	flashMap := map[string]string{}
	for _, label := range defaultMapOrder {
		fn := defaultMap[label]
		for _, cand := range []string{label + "_" + slot + ".img", label + ".img"} {
			p := filepath.Join(dumpDir, cand)
			if b, err := os.ReadFile(p); err == nil {
				parts[fn] = b
				flashMap[label] = fn
				break
			}
		}
	}
	if gpt == nil {
		for _, cand := range []string{"gpt.bin", "gpt_main0.img", "gpt.img"} {
			if b, err := os.ReadFile(filepath.Join(dumpDir, cand)); err == nil {
				gpt = b
				break
			}
		}
	}
	return &Target{
		Parts:    parts,
		FlashMap: flashMap,
		GPT:      gpt,
		Storage:  inferStorage(gpt, nil),
		Source:   "dumps:" + dumpDir,
	}, nil
}
