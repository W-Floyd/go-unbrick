package nura

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/port"
)

func TestDeviceinfoDerivesAndFlagsTodos(t *testing.T) {
	p := port.Package{
		Props: port.ParseProps("ro.product.vendor.manufacturer=motorola\nro.product.vendor.model=moto g play - 2024\nro.product.vendor.device=fogona\nro.product.cpu.abi=arm64-v8a\n"),
		DT: port.DT{Model: "fogona", SoC: "qcom,khaje", Compat: []string{"mot.fogona"}, Panels: []port.Panel{
			{Name: "a", W: 720, H: 1600}, {Name: "b", W: 720, H: 1600}}},
		Partitions: []string{"super", "vbmeta_a"}, SectorSize: 4096,
		Boot: port.Boot{HeaderVersion: 4, PageSize: 4096, Kernel: 0x8000, Ramdisk: 0x1000000, Tags: 0x100, DTB: 0x1f00000},
	}
	out := Render(Deviceinfo(p, false))
	for _, want := range []string{
		`deviceinfo_name="Motorola Moto G Play 2024"`,
		`deviceinfo_codename="motorola-fogona"`,
		`deviceinfo_screen_width="720"`,
		`deviceinfo_flash_fastboot_partition_rootfs="super"`,
		`deviceinfo_rootfs_image_sector_size="4096"`,
		`deviceinfo_flash_offset_dtb="0x01f00000"`,
		"# TODO: deviceinfo_year",
		"# TODO: deviceinfo_dtb",
		"# TODO: deviceinfo_chassis",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "initfs_udev_subsystems") {
		t.Error("the udev line belongs to the loader case only")
	}
}

func TestDeviceinfoLoaderNeedsUdev(t *testing.T) {
	out := Render(Deviceinfo(port.Package{}, true))
	if !strings.Contains(out, `deviceinfo_initfs_udev_subsystems="block"`) {
		t.Errorf("missing the loader's udev precondition:\n%s", out)
	}
}

func TestDeviceinfoPanelsDisagree(t *testing.T) {
	p := port.Package{DT: port.DT{Panels: []port.Panel{{Name: "a", W: 720, H: 1600}, {Name: "b", W: 1080, H: 2400}}}}
	out := Render(Deviceinfo(p, false))
	if strings.Contains(out, `deviceinfo_screen_width=`) || !strings.Contains(out, "# TODO: deviceinfo_screen_width") {
		t.Errorf("disagreeing panels must not set a size:\n%s", out)
	}
}
