package qfil

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"

	"go-unbrick/internal/safeguard"
)

// ReadEntry models a single <read .../> directive in a Qualcomm readprogram*.xml.
type ReadEntry struct {
	SectorSizeInBytes       int    `xml:"SECTOR_SIZE_IN_BYTES,attr"`
	FileSectorOffset        int    `xml:"file_sector_offset,attr"`
	Filename                string `xml:"filename,attr"`
	Label                   string `xml:"label,attr"`
	NumPartitionSectors     uint64 `xml:"num_partition_sectors,attr"`
	PhysicalPartitionNumber int    `xml:"physical_partition_number,attr"`
	SizeInKB                string `xml:"size_in_KB,attr"`
	Sparse                  string `xml:"sparse,attr"`
	StartByteHex            string `xml:"start_byte_hex,attr"`
	StartSector             uint64 `xml:"start_sector,attr"`
}

type readProgramXML struct {
	XMLName xml.Name    `xml:"data"`
	Reads   []ReadEntry `xml:"read"`
}

// ParseReadProgram parses a Qualcomm readprogram*.xml file into read entries.
func ParseReadProgram(xmlData []byte) ([]ReadEntry, error) {
	var root readProgramXML
	if err := xml.Unmarshal(xmlData, &root); err != nil {
		return nil, fmt.Errorf("parsing readprogram XML: %w", err)
	}
	return root.Reads, nil
}

// GenerateReadProgram creates a standard Qualcomm readprogram0.xml that dumps all
// unique per-device calibration, radio NVRAM, and identity partitions before flashing.
//
// table: the target's partition table
// additionalPartitions: optional additional partition names to protect
func GenerateReadProgram(table *Table, additionalPartitions []string) ([]byte, error) {
	sectorSize := 512
	if table != nil && table.SectorSize > 0 {
		sectorSize = int(table.SectorSize)
	}

	var entries []ReadEntry
	seen := make(map[string]bool)

	// Helper to add an entry for a Partition
	addPartitionEntry := func(p Partition) {
		name := p.Name
		if seen[strings.ToLower(name)] {
			return
		}
		seen[strings.ToLower(name)] = true

		base := safeguard.NormalizeBaseName(name)
		fn := fmt.Sprintf("backup_%s.bin", strings.ToLower(name))
		if strings.EqualFold(base, "persist") || strings.EqualFold(base, "prodpersist") {
			fn = fmt.Sprintf("backup_%s.img", strings.ToLower(name))
		}

		sizeKB := float64(p.NumSectors*uint64(sectorSize)) / 1024.0
		startHex := fmt.Sprintf("0x%X", p.StartLBA*uint64(sectorSize))

		entries = append(entries, ReadEntry{
			SectorSizeInBytes:       sectorSize,
			FileSectorOffset:        0,
			Filename:                fn,
			Label:                   name,
			NumPartitionSectors:     p.NumSectors,
			PhysicalPartitionNumber: p.LUN,
			SizeInKB:                fmt.Sprintf("%.1f", sizeKB),
			Sparse:                  "false",
			StartByteHex:            startHex,
			StartSector:             p.StartLBA,
		})
	}

	// 1. Check all partitions present in the target GPT
	if table != nil {
		for _, p := range table.Partitions {
			if safeguard.IsProtected(p.Name) {
				addPartitionEntry(p)
			}
		}
	}

	// 2. Check any additional partitions requested
	for _, name := range additionalPartitions {
		clean := strings.TrimSpace(name)
		if clean == "" || seen[strings.ToLower(clean)] {
			continue
		}
		if table != nil {
			if p, ok := table.PartitionByName(clean); ok {
				addPartitionEntry(p)
				continue
			}
		}
		// If partition is in safeguard list but not in GPT, estimate standard sector sizing
		if safeguard.IsProtected(clean) {
			seen[strings.ToLower(clean)] = true
			fn := fmt.Sprintf("backup_%s.bin", strings.ToLower(clean))
			entries = append(entries, ReadEntry{
				SectorSizeInBytes:       sectorSize,
				FileSectorOffset:        0,
				Filename:                fn,
				Label:                   clean,
				NumPartitionSectors:     2048, // 1MB default
				PhysicalPartitionNumber: 0,
				SizeInKB:                "1024.0",
				Sparse:                  "false",
				StartByteHex:            "0x0",
				StartSector:             0,
			})
		}
	}

	// Sort entries by physical partition (LUN) and start sector for efficient linear reading
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].PhysicalPartitionNumber != entries[j].PhysicalPartitionNumber {
			return entries[i].PhysicalPartitionNumber < entries[j].PhysicalPartitionNumber
		}
		return entries[i].StartSector < entries[j].StartSector
	})

	return formatReadProgramXML(entries)
}

func formatReadProgramXML(entries []ReadEntry) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<?xml version=\"1.0\" ?>\n")
	buf.WriteString("<data>\n")
	for _, e := range entries {
		buf.WriteString(fmt.Sprintf(
			"  <read SECTOR_SIZE_IN_BYTES=\"%d\" file_sector_offset=\"%d\" filename=\"%s\" label=\"%s\" num_partition_sectors=\"%d\" physical_partition_number=\"%d\" size_in_KB=\"%s\" sparse=\"%s\" start_byte_hex=\"%s\" start_sector=\"%d\"/>\n",
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

