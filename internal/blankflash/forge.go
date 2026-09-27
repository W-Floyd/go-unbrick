package blankflash

// Assemble a target blankflash from a donor's signed loader and the target's images.
//
// The output singleimage.bin carries:
//
//	index.xml, pkg.xml, default.xml   qboot recipe (generated for the target)
//	programmer.elf                    the donor's signed Firehose loader
//	<target bootloader partitions>    the target's own images
//	gpt.bin                           the target's own partition table
//	LONELY_N_SINGLE                   end sentinel
//
// By default the recipe is a *minimal restore*: flash GPT + the boot chain, with
// no storage re-provisioning. Re-provisioning (the donor's <ufs> LUN block) is
// device- and storage-specific and can worsen a brick, so it is opt-in only.
//
// The donor's backup/restore directives ARE carried over. Every genuine
// Motorola blankflash examined here (129 of 129) brackets the flash with them,
// preserving the partitions that hold per-device state -- cid, frp, hw, misc,
// persist, prodpersist, utags, devinfo, sp -- and skipping the boot components
// it is about to write. Dropping them risks losing that state if the GPT being
// flashed moves those partitions, which is exactly the cross-build case this
// tool exists for.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/safeguard"
)

// bootOrder is the fallback flash order, used only when the target's own
// recipe did not survive harvesting. It is deliberately not the whole story:
// which partitions a device flashes varies by SoC -- aop, cmnlib, cmnlib64,
// cpucp, shrm, spss1p, spss2p, uefi, XblRamdump and aop_devcfg all appear in
// genuine packages -- so Target.FlashOrder is preferred when present.
var bootOrder = []string{
	"abl", "devcfg", "hyp", "keymaster", "tz", "storsec",
	"prov", "rpm", "qupfw", "uefisecapp", "xbl_config", "xbl",
}

const (
	blankFlashBat = "@echo off\r\nqboot.exe %* fastboot singleimage.bin\r\n"
	blankFlashSh  = "#!/bin/sh\nexec \"$(dirname \"$0\")/qboot\" \"$@\" fastboot singleimage.bin\n"
)

type ForgeResult struct {
	Singleimage []byte
	Aux         map[string][]byte // qboot binaries + blank-flash scripts
	Warnings    []string
}

func indexXML(cpu, storage string) []byte {
	return []byte(fmt.Sprintf(
		"<?xml version=\"1.0\"?>\n<index>\n"+
			"\t<board id=\"440\" name=\"%s\" storage.type=\"%s\" />\n"+
			"\t<package compatible=\"protocol:qboot cpu.name:%s\" filename=\"pkg.xml\"/>\n"+
			"</index>\n",
		cpu, strings.ToUpper(storage), cpu))
}

func pkgXML() []byte {
	return []byte("<?xml version=\"1.0\"?>\n<package>\n" +
		"    <programmer filename=\"programmer.elf\"/>\n" +
		"    <recipe filename=\"default.xml\"/>\n</package>\n")
}

// reDirective matches one self-closing recipe element of the named kind.
var reDirective = regexp.MustCompile(`(?m)^[ \t]*<(backup|restore)\b[^>]*/>`)

// carryDirectives lifts the donor's backup and restore elements. They name
// partitions, not addresses, so they transfer to another device on the same
// platform unchanged.
func carryDirectives(recipes map[string][]byte) (backups, restores []string) {
	var src []byte
	for n, b := range recipes {
		if strings.HasSuffix(n, "default.xml") {
			src = b
			break
		}
	}
	if src == nil {
		return nil, nil
	}
	for _, m := range reDirective.FindAllString(string(src), -1) {
		line := "\t" + strings.TrimSpace(m)
		if strings.Contains(m, "<restore") {
			restores = append(restores, line)
		} else {
			backups = append(backups, line)
		}
	}
	return backups, restores
}

// flashOrderOf prefers the order the device's own recipe used, appending any
// mapped partition it did not mention so nothing is silently dropped.
func flashOrderOf(target *Target) []string {
	if len(target.FlashOrder) == 0 {
		return bootOrder
	}
	seen := make(map[string]bool, len(target.FlashOrder))
	out := make([]string, 0, len(target.FlashMap))
	for _, l := range target.FlashOrder {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	extra := make([]string, 0, len(target.FlashMap))
	for l := range target.FlashMap {
		if !seen[l] {
			extra = append(extra, l)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

func defaultXML(target *Target, slot, storage string, provision []byte, backups, restores []string) []byte {
	lines := []string{`<?xml version="1.0" ?>`, "<recipe>"}
	if len(backups) > 0 {
		lines = append(lines, "\t<!-- carried from the donor: preserve per-device partitions -->")
		lines = append(lines, backups...)
	}
	if len(provision) > 0 {
		lines = append(lines, "\t<!-- provisioning supplied via --provision-from -->")
		lines = append(lines, strings.TrimSpace(string(provision)))
	} else {
		lines = append(lines, fmt.Sprintf("\t<configure MemoryName=\"%s\" SkipStorageInit=\"1\"/>", storage))
	}
	lines = append(lines,
		`	<setbootablestoragedrive value="1"/>`,
		`	<print what="Flashing GPT..."/>`,
		`	<flash partition="partition" filename="gpt.bin" verbose="true"/>`,
		`	<storage operation="reinit"/>`,
		`	<print what="Flashing bootloader..."/>`,
	)
	for _, label := range flashOrderOf(target) {
		fn := target.FlashMap[label]
		if fn != "" {
			if _, ok := target.Parts[fn]; ok {
				lines = append(lines, fmt.Sprintf("\t<flash partition=\"%s_%s\" filename=\"%s\" verbose=\"true\"/>", label, slot, fn))
			}
		}
	}
	if len(restores) > 0 {
		lines = append(lines, "\t<!-- carried from the donor: put the preserved partitions back -->")
		lines = append(lines, restores...)
	}
	lines = append(lines, "</recipe>\n")
	return []byte(strings.Join(lines, "\n"))
}

func Forge(donor *Donor, target *Target, slot, storage string, provision []byte) (*ForgeResult, error) {
	var warnings []string
	if storage == "" {
		storage = firstNonEmpty(target.Storage, donor.Storage, "emmc")
	}
	storage = strings.ToLower(storage)

	if donor.Storage != "" && target.Storage != "" && strings.ToLower(donor.Storage) != strings.ToLower(target.Storage) {
		warnings = append(warnings, fmt.Sprintf(
			"donor storage (%s) != target storage (%s); using target's. "+
				"Verify the recipe's <configure MemoryName> is correct.", donor.Storage, target.Storage))
	}
	if storage == "ufs" && len(provision) == 0 {
		warnings = append(warnings,
			"UFS target with no --provision-from: the recipe skips re-provisioning "+
				"(SkipStorageInit=1) and relies on the existing UFS layout. That is right "+
				"for restoring a previously-working unit, but cannot re-create a wiped one.")
	}
	var targetParts []string
	if len(target.GPT) > 0 {
		if parts, err := safeguard.PartitionNamesFromGPT(target.GPT); err == nil {
			targetParts = parts
		}
	}

	backups, restores := carryDirectives(donor.Recipes)
	if len(backups) == 0 {
		backups, restores = safeguard.SynthesizeDirectives(targetParts, flashOrderOf(target))
		warnings = append(warnings,
			"donor recipe carries no <backup> directives: synthesized safe <backup> and <restore> directives "+
				"to preserve per-device unique calibration and identity partitions across the flash.")
	} else if len(targetParts) > 0 {
		// Donor has backup directives, but verify that all protected partitions in the target GPT are safeguarded
		backupText := strings.Join(backups, "\n")
		var missing []string
		for _, tp := range targetParts {
			if safeguard.IsProtected(tp) {
				clean := strings.ToLower(tp)
				base := safeguard.NormalizeBaseName(tp)
				if !strings.Contains(backupText, `name="`+clean+`"`) && !strings.Contains(backupText, `name="`+base+`"`) {
					missing = append(missing, fmt.Sprintf("\t<backup name=\"%s\"/>", clean))
				}
			}
		}
		if len(missing) > 0 {
			commitIdx := -1
			for i, b := range backups {
				if strings.Contains(b, `<backup commit="1"/>`) {
					commitIdx = i
					break
				}
			}
			if commitIdx >= 0 {
				newBackups := make([]string, 0, len(backups)+len(missing)+1)
				newBackups = append(newBackups, backups[:commitIdx]...)
				newBackups = append(newBackups, "\t<!-- augmented safeguards: preserve target-specific protected partitions -->")
				newBackups = append(newBackups, missing...)
				newBackups = append(newBackups, backups[commitIdx:]...)
				backups = newBackups
			} else {
				backups = append(backups, missing...)
			}
			warnings = append(warnings, fmt.Sprintf(
				"donor recipe was missing %d protected partitions present in target GPT: augmented backup directives.", len(missing)))
		}
	}
	if target.GPT == nil {
		warnings = append(warnings, "no target gpt.bin: the GPT flash step will fail. Supply --target-gpt.")
	}

	cpu := donor.CPUName
	if cpu == "" {
		cpu = "SM_DIVAR"
	}
	recs := []Record{
		{Name: "index.xml", Data: indexXML(cpu, storage)},
		{Name: "pkg.xml", Data: pkgXML()},
		{Name: "default.xml", Data: defaultXML(target, slot, storage, provision, backups, restores)},
		{Name: "programmer.elf", Data: donor.Programmer},
	}
	for _, label := range flashOrderOf(target) {
		fn := target.FlashMap[label]
		if fn != "" {
			if v, ok := target.Parts[fn]; ok {
				recs = append(recs, Record{Name: fn, Data: v})
			}
		}
	}
	if target.GPT != nil {
		recs = append(recs, Record{Name: "gpt.bin", Data: target.GPT})
	}

	blob, err := Build(WithTrailer(recs))
	if err != nil {
		return nil, err
	}

	aux := map[string][]byte{}
	for n, b := range donor.Qboot {
		aux[n] = b
	}
	if _, ok := aux["blank-flash.bat"]; !ok {
		aux["blank-flash.bat"] = []byte(blankFlashBat)
	}
	if _, ok := aux["blank-flash.sh"]; !ok {
		aux["blank-flash.sh"] = []byte(blankFlashSh)
	}

	return &ForgeResult{Singleimage: blob, Aux: aux, Warnings: warnings}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
