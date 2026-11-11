package vendor

import (
	"reflect"
	"testing"
)

func TestParseNeusoftVersions(t *testing.T) {
	data := []byte("ALL_VERSION = 2350001.00\n" +
		"BOOT_VERSION = BL_A.23.D0.05.00.01.00\n" +
		"SOC_VERSION = SS_A.23.D0.05.00.01.00\n" +
		"MCU_VERSION = MS_A.23.D0.05.00.01.00\n" +
		"CAMERA_VERSION = CS_A.23.D0.05.00.01.00\n")
	got := ParseNeusoftVersions(data)
	want := NeusoftVersions{
		AllVersion:    "2350001.00",
		BootVersion:   "BL_A.23.D0.05.00.01.00",
		SocVersion:    "SS_A.23.D0.05.00.01.00",
		McuVersion:    "MS_A.23.D0.05.00.01.00",
		CameraVersion: "CS_A.23.D0.05.00.01.00",
	}
	if got != want {
		t.Fatalf("ParseNeusoftVersions = %+v, want %+v", got, want)
	}
}

func TestParseNeusoftRootfsManifest(t *testing.T) {
	data := []byte("total count = 6\n" +
		"part size = 209715200\n" +
		"part size = 209715200\n" +
		"part size = 209715200\n" +
		"part size = 209715200\n" +
		"part size = 209715200\n" +
		"part size = 50585600\n")
	got, ok := ParseNeusoftRootfsManifest(data)
	if !ok {
		t.Fatal("expected ok=true for a well-formed manifest")
	}
	want := NeusoftRootfsManifest{PartSizes: []int64{209715200, 209715200, 209715200, 209715200, 209715200, 50585600}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseNeusoftRootfsManifest = %+v, want %+v", got, want)
	}
}

func TestParseNeusoftRootfsManifestNotThisFormat(t *testing.T) {
	if _, ok := ParseNeusoftRootfsManifest([]byte("hello\nworld\n")); ok {
		t.Fatal("expected ok=false for unrelated content")
	}
}

func TestNeusoftRegistered(t *testing.T) {
	for _, d := range Drivers() {
		if d.ID() == "neusoft" {
			if d.Platform() != PlatformTelechips {
				t.Fatalf("neusoft Platform() = %q, want %q", d.Platform(), PlatformTelechips)
			}
			return
		}
	}
	t.Fatal("neusoft driver not registered")
}

// TestNeusoftDoesNotSupplyAZipPassword makes sure neusoft stays recognition
// -only on this point: the zip password here is not a vendor derivation (see
// alpine.go's "FBDMI" for contrast) -- it's a plain digit sequence brute
// force finds on its own, and neusoft must not implement ZipPassworder at
// all, let alone return one.
func TestNeusoftDoesNotSupplyAZipPassword(t *testing.T) {
	if _, ok := any(neusoft{}).(ZipPassworder); ok {
		t.Fatal("neusoft should not implement ZipPassworder: its zip password is found by brute force, not bundled")
	}
}
