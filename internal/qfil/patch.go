package qfil

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
)

// PatchEntry represents a single <patch .../> directive in a patch*.xml file.
type PatchEntry struct {
	SectorSizeInBytes       int    `xml:"SECTOR_SIZE_IN_BYTES,attr"`
	ByteOffset              int    `xml:"byte_offset,attr"`
	Filename                string `xml:"filename,attr"`
	PhysicalPartitionNumber int    `xml:"physical_partition_number,attr"`
	SizeInBytes             int    `xml:"size_in_bytes,attr"`
	StartSector             uint64 `xml:"start_sector,attr"`
	Value                   string `xml:"value,attr"`
	What                    string `xml:"what,attr"`
}

type patchXML struct {
	XMLName xml.Name     `xml:"patches"`
	Patches []PatchEntry `xml:"patch"`
}

// ParsePatch parses a Qualcomm patch*.xml file into patch entries.
func ParsePatch(xmlData []byte) ([]PatchEntry, error) {
	var root patchXML
	if err := xml.Unmarshal(xmlData, &root); err != nil {
		return nil, fmt.Errorf("parsing patch XML: %w", err)
	}
	return root.Patches, nil
}

// GeneratePatch creates a standard Qualcomm patch0.xml file.
// If table is non-nil, standard GPT header fixup patches are included — one set
// per physical LUN for a multi-LUN UFS table, else for LUN 0 alone. edl computes
// NUM_DISK_SECTORS per physical partition, so the backup-GPT location is fixed up
// correctly for each LUN's actual size.
func GeneratePatch(table *Table) []byte {
	sectorSize := 512
	if table != nil && table.SectorSize > 0 {
		sectorSize = int(table.SectorSize)
	}

	luns := []int{0}
	if table != nil && len(table.LUNGPT) > 0 {
		luns = luns[:0]
		for lun := range table.LUNGPT {
			luns = append(luns, lun)
		}
		sort.Ints(luns)
	}

	var buf bytes.Buffer
	buf.WriteString("<?xml version=\"1.0\" ?>\n")
	buf.WriteString("<patches>\n")
	for _, lun := range luns {
		buf.WriteString(fmt.Sprintf(
			"  <patch SECTOR_SIZE_IN_BYTES=\"%d\" byte_offset=\"24\" filename=\"DISK\" physical_partition_number=\"%d\" size_in_bytes=\"8\" start_sector=\"1\" value=\"NUM_DISK_SECTORS-1.\" what=\"Update Primary GPT header with Current LBA.\"/>\n",
			sectorSize, lun))
		buf.WriteString(fmt.Sprintf(
			"  <patch SECTOR_SIZE_IN_BYTES=\"%d\" byte_offset=\"32\" filename=\"DISK\" physical_partition_number=\"%d\" size_in_bytes=\"8\" start_sector=\"1\" value=\"NUM_DISK_SECTORS-1.\" what=\"Update Primary GPT header with Backup LBA.\"/>\n",
			sectorSize, lun))
		buf.WriteString(fmt.Sprintf(
			"  <patch SECTOR_SIZE_IN_BYTES=\"%d\" byte_offset=\"88\" filename=\"DISK\" physical_partition_number=\"%d\" size_in_bytes=\"4\" start_sector=\"1\" value=\"CRC32(1,92)\" what=\"Update Primary GPT header with CRC32.\"/>\n",
			sectorSize, lun))
	}
	buf.WriteString("</patches>\n")
	return buf.Bytes()
}

