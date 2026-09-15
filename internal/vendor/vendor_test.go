package vendor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go-unbrick/internal/blankflash"
)

func TestRegistryLookup(t *testing.T) {
	if d, ok := For("motorola"); !ok || d.ID() != "motorola" {
		t.Errorf("For(motorola): %v %v", d, ok)
	}
	if d, ok := ForOEMID("02E8"); !ok || d.ID() != "motorola" {
		t.Errorf("ForOEMID(02E8) should be motorola: %v %v", d, ok)
	}
	if d, ok := ForOEMID("0020"); !ok || d.ID() != "samsung" {
		t.Errorf("ForOEMID(0020) should be samsung: %v %v", d, ok)
	}
	if _, ok := ForOEMID("FFFF"); ok {
		t.Error("unknown OEM_ID should not resolve")
	}
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()

	// A SINGLE_N_LONELY container -> motorola.
	moto := filepath.Join(dir, "singleimage.bin")
	blob, _ := blankflash.Build(blankflash.WithTrailer([]blankflash.Record{{Name: "programmer.elf", Data: []byte("x")}}))
	os.WriteFile(moto, blob, 0o644)
	if d, ok := Detect(moto); !ok || d.ID() != "motorola" {
		t.Errorf("Detect(singleimage) should be motorola: %v %v", d, ok)
	}

	// A .pit table -> samsung.
	pit := filepath.Join(dir, "STARQLTE.pit")
	os.WriteFile(pit, []byte("PIT dummy"), 0o644)
	if d, ok := Detect(pit); !ok || d.ID() != "samsung" {
		t.Errorf("Detect(.pit) should be samsung: %v %v", d, ok)
	}

	// Something unrecognized.
	other := filepath.Join(dir, "random.txt")
	os.WriteFile(other, []byte("hello"), 0o644)
	if _, ok := Detect(other); ok {
		t.Error("Detect(random) should not match")
	}
}

func TestPlatforms(t *testing.T) {
	cases := map[string]string{"motorola": PlatformQualcomm, "samsung": PlatformQualcomm, "mediatek": PlatformMediaTek}
	for id, want := range cases {
		d, ok := For(id)
		if !ok {
			t.Fatalf("driver %q not registered", id)
		}
		if d.Platform() != want {
			t.Errorf("%s platform: got %q want %q", id, d.Platform(), want)
		}
	}
}

func TestDetectMediaTek(t *testing.T) {
	dir := t.TempDir()
	scatter := filepath.Join(dir, "MT6765_Android_scatter_blankflash.txt")
	os.WriteFile(scatter, []byte("- partition_index: SYS0\n"), 0o644)
	if d, ok := Detect(scatter); !ok || d.ID() != "mediatek" {
		t.Errorf("Detect(scatter) should be mediatek: %v %v", d, ok)
	}
	// A MediaTek OEM_ID space is separate; it declares none.
	if m, _ := For("mediatek"); len(m.OEMIDs()) != 0 {
		t.Error("mediatek should declare no Qualcomm OEM_IDs")
	}
}

func TestSamsungOpsUnsupported(t *testing.T) {
	s, _ := For("samsung")
	if _, err := s.IngestDonor("x"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("IngestDonor should wrap ErrUnsupported: %v", err)
	}
	if _, err := s.HarvestStock(TargetSource{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("HarvestStock should wrap ErrUnsupported: %v", err)
	}
	if _, err := s.Assemble(nil, nil, AssembleOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Assemble should wrap ErrUnsupported: %v", err)
	}
}
