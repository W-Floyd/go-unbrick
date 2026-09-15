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

import (
	"fmt"
	"strings"
)

// bootOrder is the flash order used by Motorola stock recipes (xbl last).
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

func defaultXML(target *Target, slot, storage string, provision []byte) []byte {
	lines := []string{`<?xml version="1.0" ?>`, "<recipe>"}
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
	for _, label := range bootOrder {
		fn := target.FlashMap[label]
		if fn != "" {
			if _, ok := target.Parts[fn]; ok {
				lines = append(lines, fmt.Sprintf("\t<flash partition=\"%s_%s\" filename=\"%s\" verbose=\"true\"/>", label, slot, fn))
			}
		}
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
		{Name: "default.xml", Data: defaultXML(target, slot, storage, provision)},
		{Name: "programmer.elf", Data: donor.Programmer},
	}
	for _, label := range bootOrder {
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
