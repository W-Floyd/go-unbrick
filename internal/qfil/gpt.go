package qfil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"go-unbrick/internal/blankflash"
)

const (
	gptSignature = "EFI PART"
	defaultSectorSize = 512
)

// Partition represents one entry in a GPT partition table.
type Partition struct {
	Name        string
	StartLBA    uint64
	EndLBA      uint64
	NumSectors  uint64
	LUN         int
	TypeGUID    [16]byte
	UniqueGUID  [16]byte
	Attributes  uint64
}

// Table holds the parsed GPT partitions and disk metadata.
type Table struct {
	SectorSize uint32
	DiskGUID   [16]byte
	Partitions []Partition
	Raw        []byte
	// LUNGPT maps a physical LUN to its own flashable primary-GPT image
	// (gpt_mainN.bin). Populated only for multi-LUN UFS tables unpacked from a
	// SINGLE_N_LONELY container; nil for a single eMMC/plain GPT.
	LUNGPT map[int][]byte
}

// PartitionByName looks up a partition by label. If not found directly, it tries
// matching with slot suffixes (e.g. "xbl" -> "xbl_a"). Case-insensitive.
func (t *Table) PartitionByName(name string) (Partition, bool) {
	target := strings.ToLower(name)
	for _, p := range t.Partitions {
		if strings.ToLower(p.Name) == target {
			return p, true
		}
	}
	// Try with standard slot suffixes if not already qualified.
	if !strings.HasSuffix(target, "_a") && !strings.HasSuffix(target, "_b") {
		for _, p := range t.Partitions {
			pLower := strings.ToLower(p.Name)
			if pLower == target+"_a" || pLower == target+"_b" {
				return p, true
			}
		}
	}
	// Try without slot suffix if caller searched with slot.
	base := strings.TrimSuffix(strings.TrimSuffix(target, "_a"), "_b")
	for _, p := range t.Partitions {
		if strings.ToLower(p.Name) == base {
			return p, true
		}
	}
	return Partition{}, false
}

// ParseGPT parses a GPT partition table from raw disk or image bytes.
// Accepts raw dumps starting with protective MBR (header at offset 512),
// header-first dumps (header at offset 0), or scans for the "EFI PART" signature.
//
// A Motorola SINGLE_N_LONELY container (UFS gpt.bin, several gpt_mainN.bin
// packed together) is unpacked and every LUN parsed: the returned Table merges
// all partitions, tags each with its physical LUN, and carries the per-LUN
// flashable images in LUNGPT. Parsing the container as one blob would key on the
// first inner header at a non-sector-aligned offset and misread everything.
func ParseGPT(data []byte) (*Table, error) {
	if blankflash.IsContainer(data) {
		return parseContainerGPT(data)
	}
	return ParseGPTWithLUN(data, 0)
}

// parseContainerGPT unpacks a SINGLE_N_LONELY gpt.bin and merges its per-LUN
// gpt_mainN.bin images into one Table.
func parseContainerGPT(data []byte) (*Table, error) {
	recs, err := blankflash.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("unpacking gpt container: %w", err)
	}
	merged := &Table{Raw: data, LUNGPT: map[int][]byte{}}
	var luns []int
	byLUN := map[int]*Table{}
	for _, r := range recs {
		lun, ok := gptMainLUN(r.Name)
		if !ok {
			continue
		}
		t, err := ParseGPTWithLUN(r.Data, lun)
		if err != nil {
			continue // a per-LUN table we cannot read is skipped, not fatal
		}
		merged.LUNGPT[lun] = r.Data
		byLUN[lun] = t
		luns = append(luns, lun)
	}
	if len(luns) == 0 {
		return nil, fmt.Errorf("no gpt_main* images in container")
	}
	sort.Ints(luns)
	for _, lun := range luns {
		t := byLUN[lun]
		if merged.SectorSize == 0 {
			merged.SectorSize = t.SectorSize
			merged.DiskGUID = t.DiskGUID
		}
		merged.Partitions = append(merged.Partitions, t.Partitions...)
	}
	return merged, nil
}

// gptMainLUN extracts the physical LUN index N from a "gpt_mainN.bin" record
// name (the backup image is "gpt_backupN.bin"; only primaries are flashed here).
func gptMainLUN(name string) (int, bool) {
	rest, ok := strings.CutPrefix(name, "gpt_main")
	if !ok {
		return 0, false
	}
	rest = strings.TrimSuffix(rest, ".bin")
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ParseGPTWithLUN parses GPT bytes and tags the resulting partitions with physical LUN.
func ParseGPTWithLUN(data []byte, lun int) (*Table, error) {
	if len(data) < 512 {
		return nil, fmt.Errorf("data too short for GPT header (%d bytes)", len(data))
	}

	headerOffset := -1
	sectorSize := defaultSectorSize

	if bytes.HasPrefix(data, []byte(gptSignature)) {
		headerOffset = 0
	} else if len(data) >= 1024 && bytes.Equal(data[512:520], []byte(gptSignature)) {
		headerOffset = 512
	} else if idx := bytes.Index(data, []byte(gptSignature)); idx >= 0 {
		headerOffset = idx
	}

	if headerOffset < 0 {
		return nil, fmt.Errorf("no EFI PART signature found")
	}

	header := data[headerOffset:]
	if len(header) < 92 {
		return nil, fmt.Errorf("truncated GPT header (%d bytes)", len(header))
	}

	headerSize := binary.LittleEndian.Uint32(header[12:16])
	if headerSize < 92 || int(headerSize) > len(header) {
		return nil, fmt.Errorf("invalid GPT header size: %d", headerSize)
	}

	currentLBA := binary.LittleEndian.Uint64(header[24:32])
	if currentLBA == 1 && headerOffset > 0 {
		sectorSize = headerOffset
	}

	var diskGUID [16]byte
	copy(diskGUID[:], header[56:72])

	partEntryLBA := binary.LittleEndian.Uint64(header[72:80])
	numEntries := binary.LittleEndian.Uint32(header[80:84])
	entrySize := binary.LittleEndian.Uint32(header[84:88])

	if entrySize < 128 || numEntries == 0 || numEntries > 1024 {
		return nil, fmt.Errorf("invalid partition entry table: %d entries of %d bytes", numEntries, entrySize)
	}

	// Calculate partition array offset.
	var partOffset int
	if currentLBA > 0 && partEntryLBA >= currentLBA {
		partOffset = headerOffset + int(partEntryLBA-currentLBA)*sectorSize
	} else if headerOffset >= sectorSize {
		partOffset = headerOffset - sectorSize + int(partEntryLBA)*sectorSize
	} else {
		partOffset = headerOffset + sectorSize
	}

	if partOffset+int(numEntries*entrySize) > len(data) {
		return nil, fmt.Errorf("partition entry array exceeds data boundary (need %d bytes, have %d)",
			partOffset+int(numEntries*entrySize), len(data))
	}

	var parts []Partition
	var zeroGUID [16]byte

	for i := uint32(0); i < numEntries; i++ {
		entry := data[partOffset+int(i*entrySize) : partOffset+int((i+1)*entrySize)]
		var typeGUID, uniqueGUID [16]byte
		copy(typeGUID[:], entry[0:16])
		if typeGUID == zeroGUID {
			continue // Unused entry
		}
		copy(uniqueGUID[:], entry[16:32])
		startLBA := binary.LittleEndian.Uint64(entry[32:40])
		endLBA := binary.LittleEndian.Uint64(entry[40:48])
		attrs := binary.LittleEndian.Uint64(entry[48:56])

		// Partition name is UTF-16LE in bytes 56..128 (36 code units)
		nameRaw := entry[56:128]
		u16 := make([]uint16, 36)
		for j := 0; j < 36; j++ {
			u16[j] = binary.LittleEndian.Uint16(nameRaw[j*2 : j*2+2])
		}
		name := strings.TrimRight(string(utf16.Decode(u16)), "\x00 ")

		numSectors := uint64(0)
		if endLBA >= startLBA {
			numSectors = endLBA - startLBA + 1
		}

		parts = append(parts, Partition{
			Name:       name,
			StartLBA:   startLBA,
			EndLBA:     endLBA,
			NumSectors: numSectors,
			LUN:        lun,
			TypeGUID:   typeGUID,
			UniqueGUID: uniqueGUID,
			Attributes: attrs,
		})
	}

	return &Table{
		SectorSize: uint32(sectorSize),
		DiskGUID:   diskGUID,
		Partitions: parts,
		Raw:        data,
	}, nil
}

