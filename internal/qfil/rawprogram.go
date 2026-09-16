package qfil

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// ProgramEntry models a single <program .../> directive in a Qualcomm rawprogram*.xml.
type ProgramEntry struct {
	SectorSizeInBytes       int     `xml:"SECTOR_SIZE_IN_BYTES,attr"`
	FileSectorOffset        int     `xml:"file_sector_offset,attr"`
	Filename                string  `xml:"filename,attr"`
	Label                   string  `xml:"label,attr"`
	NumPartitionSectors     uint64  `xml:"num_partition_sectors,attr"`
	PhysicalPartitionNumber int     `xml:"physical_partition_number,attr"`
	SizeInKB                string  `xml:"size_in_KB,attr"`
	Sparse                  string  `xml:"sparse,attr"`
	StartByteHex            string  `xml:"start_byte_hex,attr"`
	StartSector             uint64  `xml:"start_sector,attr"`
}

type rawProgramXML struct {
	XMLName  xml.Name       `xml:"data"`
	Programs []ProgramEntry `xml:"program"`
}

// ParseRawProgram parses a Qualcomm rawprogram*.xml file into program entries.
func ParseRawProgram(xmlData []byte) ([]ProgramEntry, error) {
	var root rawProgramXML
	if err := xml.Unmarshal(xmlData, &root); err != nil {
		return nil, fmt.Errorf("parsing rawprogram XML: %w", err)
	}
	return root.Programs, nil
}

// GenerateRawProgram creates a standard Qualcomm rawprogram0.xml from a parsed GPT Table
// and a collection of target partition files.
//
// table: the target's partition table
// parts: map of filename -> bytes on disk
// flashMap: map of label -> filename
// flashOrder: order to flash partitions in (or nil to auto-order)
// gptFilename: filename for the primary GPT image (e.g. "gpt_main0.bin")
// slot: default slot to flash ("a" or "b", defaults to "a")
func GenerateRawProgram(table *Table, parts map[string][]byte, flashMap map[string]string, flashOrder []string, gptFilename string, slot string) ([]byte, error) {
	if slot == "" {
		slot = "a"
	}

	sectorSize := 512
	if table != nil && table.SectorSize > 0 {
		sectorSize = int(table.SectorSize)
	}

	var entries []ProgramEntry

	// 1. Primary GPT at sector 0 (if present)
	if gptFilename != "" {
		numSectors := uint64(34) // Standard protective MBR (1) + GPT header (1) + 128 entries (32)
		if table != nil && len(table.Raw) > 0 {
			numSectors = uint64((len(table.Raw) + sectorSize - 1) / sectorSize)
		}
		entries = append(entries, ProgramEntry{
			SectorSizeInBytes:       sectorSize,
			FileSectorOffset:        0,
			Filename:                gptFilename,
			Label:                   "PrimaryGPT",
			NumPartitionSectors:     numSectors,
			PhysicalPartitionNumber: 0,
			SizeInKB:                fmt.Sprintf("%.1f", float64(numSectors*uint64(sectorSize))/1024.0),
			Sparse:                  "false",
			StartByteHex:            "0x0",
			StartSector:             0,
		})
	}

	// 2. Decide labels and order
	var labels []string
	seen := map[string]bool{}

	// Prefer caller's flashOrder
	for _, l := range flashOrder {
		if !seen[l] {
			seen[l] = true
			labels = append(labels, l)
		}
	}

	// Add any mapped partitions not in flashOrder
	var extra []string
	for l := range flashMap {
		if !seen[l] {
			extra = append(extra, l)
		}
	}
	sort.Strings(extra)
	for _, l := range extra {
		seen[l] = true
		labels = append(labels, l)
	}

	// If neither flashOrder nor flashMap was supplied, use parts keys directly
	if len(labels) == 0 {
		var pnames []string
		for fn := range parts {
			base := strings.TrimSuffix(fn, ".elf")
			base = strings.TrimSuffix(base, ".mbn")
			base = strings.TrimSuffix(base, ".bin")
			base = strings.TrimSuffix(base, ".img")
			if !seen[base] {
				seen[base] = true
				pnames = append(pnames, base)
			}
		}
		sort.Strings(pnames)
		labels = append(labels, pnames...)
	}

	// 3. For each label, match with GPT partition
	for _, label := range labels {
		fn := flashMap[label]
		if fn == "" {
			// Find filename matching label in parts
			for partFn := range parts {
				base := strings.TrimSuffix(partFn, ".elf")
				base = strings.TrimSuffix(base, ".mbn")
				base = strings.TrimSuffix(base, ".bin")
				base = strings.TrimSuffix(base, ".img")
				if strings.EqualFold(base, label) || strings.EqualFold(base, label+"_"+slot) {
					fn = partFn
					break
				}
			}
		}
		if fn == "" {
			continue // No partition payload file for this label
		}

		// Try matching label with slot in GPT
		candNames := []string{
			label + "_" + slot,
			label,
			label + "_a",
			label + "_b",
		}

		var matchedPart *Partition
		if table != nil {
			for _, cand := range candNames {
				if p, ok := table.PartitionByName(cand); ok {
					matchedPart = &p
					break
				}
			}
		}

		var startSec, numSec uint64
		var lun int
		if matchedPart != nil {
			startSec = matchedPart.StartLBA
			numSec = matchedPart.NumSectors
			lun = matchedPart.LUN
		} else {
			// If not in GPT, estimate from parts data length
			dataLen := uint64(len(parts[fn]))
			if dataLen == 0 {
				dataLen = 512
			}
			numSec = (dataLen + uint64(sectorSize) - 1) / uint64(sectorSize)
			startSec = 0
			lun = 0
		}

		targetLabel := label
		if matchedPart != nil {
			targetLabel = matchedPart.Name
		} else if !strings.HasSuffix(targetLabel, "_"+slot) {
			targetLabel = targetLabel + "_" + slot
		}

		sizeKB := float64(numSec*uint64(sectorSize)) / 1024.0
		startHex := fmt.Sprintf("0x%X", startSec*uint64(sectorSize))

		entries = append(entries, ProgramEntry{
			SectorSizeInBytes:       sectorSize,
			FileSectorOffset:        0,
			Filename:                fn,
			Label:                   targetLabel,
			NumPartitionSectors:     numSec,
			PhysicalPartitionNumber: lun,
			SizeInKB:                fmt.Sprintf("%.1f", sizeKB),
			Sparse:                  "false",
			StartByteHex:            startHex,
			StartSector:             startSec,
		})
	}

	return formatRawProgramXML(entries)
}

func formatRawProgramXML(entries []ProgramEntry) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<?xml version=\"1.0\" ?>\n")
	buf.WriteString("<data>\n")
	for _, e := range entries {
		buf.WriteString(fmt.Sprintf(
			"  <program SECTOR_SIZE_IN_BYTES=\"%d\" file_sector_offset=\"%d\" filename=\"%s\" label=\"%s\" num_partition_sectors=\"%d\" physical_partition_number=\"%d\" size_in_KB=\"%s\" sparse=\"%s\" start_byte_hex=\"%s\" start_sector=\"%d\"/>\n",
			e.SectorSizeInBytes,
			e.FileSectorOffset,
			xmlEscape(e.Filename),
			xmlEscape(e.Label),
			e.NumPartitionSectors,
			e.PhysicalPartitionNumber,
			e.SizeInKB,
			e.Sparse,
			e.StartByteHex,
			e.StartSector,
		))
	}
	buf.WriteString("</data>\n")
	return buf.Bytes(), nil
}

func xmlEscape(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
