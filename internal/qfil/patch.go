package qfil

import (
	"bytes"
	"encoding/xml"
	"fmt"
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
// If table is non-nil, standard GPT header fixup patches are included.
func GeneratePatch(table *Table) []byte {
	sectorSize := 512
	if table != nil && table.SectorSize > 0 {
		sectorSize = int(table.SectorSize)
	}

	var buf bytes.Buffer
	buf.WriteString("<?xml version=\"1.0\" ?>\n")
	buf.WriteString("<patches>\n")
	buf.WriteString(fmt.Sprintf(
		"  <patch SECTOR_SIZE_IN_BYTES=\"%d\" byte_offset=\"24\" filename=\"DISK\" physical_partition_number=\"0\" size_in_bytes=\"8\" start_sector=\"1\" value=\"NUM_DISK_SECTORS-1.\" what=\"Update Primary GPT header with Current LBA.\"/>\n",
		sectorSize))
	buf.WriteString(fmt.Sprintf(
		"  <patch SECTOR_SIZE_IN_BYTES=\"%d\" byte_offset=\"32\" filename=\"DISK\" physical_partition_number=\"0\" size_in_bytes=\"8\" start_sector=\"1\" value=\"NUM_DISK_SECTORS-1.\" what=\"Update Primary GPT header with Backup LBA.\"/>\n",
		sectorSize))
	buf.WriteString(fmt.Sprintf(
		"  <patch SECTOR_SIZE_IN_BYTES=\"%d\" byte_offset=\"88\" filename=\"DISK\" physical_partition_number=\"0\" size_in_bytes=\"4\" start_sector=\"1\" value=\"CRC32(1,92)\" what=\"Update Primary GPT header with CRC32.\"/>\n",
		sectorSize))
	buf.WriteString("</patches>\n")
	return buf.Bytes()
}

