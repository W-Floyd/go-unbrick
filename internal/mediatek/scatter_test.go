package mediatek

import "testing"

const flatScatter = `- general: MTK_PLATFORM_CFG
  info:
    - platform: MT6765
      project: k65v1_64_bsp
      storage: EMMC
- partition_index: SYS0
  partition_name: preloader
  file_name: preloader.bin
  is_download: true
- partition_index: SYS1
  partition_name: lk
  file_name: lk.img
  is_download: true
`

// Newer dialect: partitions nested under storage_type -> description.
const nestedScatter = `- general: MTK_PLATFORM_CFG
  info:
    - platform: MT6853
      project: k6853v1_64_6360
- storage_type: UFS
  description:
    - general: MTK_STORAGE_CFG
      info:
        - storage: UFS
    - partition_index: SYS0
      partition_name: preloader
      file_name: preloader.bin
      is_download: true
`

func TestParseFlat(t *testing.T) {
	info, err := ParseScatter([]byte(flatScatter), "MT6765_Android_scatter.txt")
	if err != nil {
		t.Fatal(err)
	}
	if info.Chip != "MT6765" || info.Project != "k65v1_64_bsp" || info.Storage != "EMMC" {
		t.Errorf("meta: %+v", info)
	}
	if len(info.Partitions) != 2 || info.Partitions[0].Name != "preloader" || !info.Partitions[0].Download {
		t.Errorf("partitions: %+v", info.Partitions)
	}
}

func TestParseNested(t *testing.T) {
	info, err := ParseScatter([]byte(nestedScatter), "MT6853_Android_scatter.txt")
	if err != nil {
		t.Fatal(err)
	}
	if info.Chip != "MT6853" || info.Storage != "UFS" {
		t.Errorf("meta: %+v", info)
	}
	if len(info.Partitions) != 1 || info.Partitions[0].Name != "preloader" {
		t.Errorf("nested partitions not walked: %+v", info.Partitions)
	}
}

func TestChipFromFilenameFallback(t *testing.T) {
	// No platform field; chip must come from the scatter filename.
	info, err := ParseScatter([]byte("- partition_index: SYS0\n  partition_name: preloader\n"), "MT6768_Android_scatter_blankflash.txt")
	if err != nil {
		t.Fatal(err)
	}
	if info.Chip != "MT6768" {
		t.Errorf("chip from filename: got %q", info.Chip)
	}
}

func TestNoChipErrors(t *testing.T) {
	if _, err := ParseScatter([]byte("- partition_name: preloader\n"), "unknown.txt"); err == nil {
		t.Error("expected error when no chip can be derived")
	}
}
