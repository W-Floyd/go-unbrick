package qfil

import (
	"fmt"

	"go-unbrick/internal/blankflash"
)

const (
	defaultProgrammerName = "prog_firehose_lite.elf"
	defaultGPTName        = "gpt_main0.bin"

	flashScriptSh = `#!/bin/sh
# Flash minimal boot recovery partitions via edl (bkerler/edl)
set -e
LOADER="prog_firehose_lite.elf"
echo "Connecting to Qualcomm EDL 9008 device with $LOADER..."
edl --loader="$LOADER" --rawprogram=rawprogram0.xml --patch=patch0.xml "$@"
echo "Flashing complete. Rebooting to bootloader..."
edl --reset
`

	flashScriptBat = `@echo off
set LOADER=prog_firehose_lite.elf
echo Connecting to Qualcomm EDL 9008 device with %LOADER%...
edl --loader=%LOADER% --rawprogram=rawprogram0.xml --patch=patch0.xml %*
if errorlevel 1 goto err
echo Flashing complete. Rebooting to bootloader...
edl --reset
goto end
:err
echo Flashing failed!
:end
`
)

// AssembleOptions specifies configuration for QFIL package generation.
type AssembleOptions struct {
	Slot      string
	Storage   string
	Provision []byte
}

// Assemble builds a standard Qualcomm QFIL/Firehose recovery bundle from a donor's
// signed Firehose programmer and a target device's harvested stock boot chain.
//
// The output contains:
//   - prog_firehose_lite.elf: donor's signed Firehose programmer
//   - gpt_main0.bin: target's partition table
//   - <partition images>: target's own boot chain (xbl, abl, tz, rpm, etc.)
//   - rawprogram0.xml: generated partition flashing directives
//   - patch0.xml: standard GPT header/backup CRC fixup patches
//   - flash.sh / flash.bat: automated unbrick scripts invoking edl
func Assemble(d *blankflash.Donor, t *blankflash.Target, opts AssembleOptions) (*blankflash.ForgeResult, error) {
	if d == nil || len(d.Programmer) == 0 {
		return nil, fmt.Errorf("donor provides no signed Firehose programmer")
	}
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}

	slot := opts.Slot
	if slot == "" {
		slot = "a"
	}

	var warnings []string
	aux := map[string][]byte{}

	// 1. Firehose Programmer
	aux[defaultProgrammerName] = d.Programmer

	// 2. Target GPT
	var table *Table
	gptFilename := ""
	if len(t.GPT) > 0 {
		var err error
		table, err = ParseGPT(t.GPT)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("failed to parse target GPT: %v (rawprogram sectors will be estimated)", err))
		}
		gptFilename = defaultGPTName
		aux[gptFilename] = t.GPT
	} else {
		warnings = append(warnings, "no target GPT provided; partition sector offsets will be estimated")
	}

	// 3. Target Boot Partitions
	for fn, data := range t.Parts {
		aux[fn] = data
	}

	// 4. Generate rawprogram0.xml
	rawProg, err := GenerateRawProgram(table, t.Parts, t.FlashMap, t.FlashOrder, gptFilename, slot)
	if err != nil {
		return nil, fmt.Errorf("generating rawprogram0.xml: %w", err)
	}
	aux["rawprogram0.xml"] = rawProg

	// 5. Generate patch0.xml
	aux["patch0.xml"] = GeneratePatch(table)

	// 6. Automated flashing scripts
	aux["flash.sh"] = []byte(flashScriptSh)
	aux["flash.bat"] = []byte(flashScriptBat)

	return &blankflash.ForgeResult{
		Singleimage: nil,
		Aux:         aux,
		Warnings:    warnings,
	}, nil
}
