package nura

import (
	"strings"
	"testing"
)

func TestParseFstab(t *testing.T) {
	got := ParseFstab(`# c
system /system erofs ro wait,logical,first_stage_mount
/dev/block/bootdevice/by-name/modem /vendor/firmware_mnt ext4 ro wait,slotselect
`)
	if len(got) != 2 || !got[0].Logical || got[1].Logical || got[1].Source != "modem" {
		t.Errorf("got %+v", got)
	}
}

func TestDeviceinfoDerivesAndFlagsTodos(t *testing.T) {
	p := Package{
		Props: ParseProps("ro.product.vendor.manufacturer=motorola\nro.product.vendor.model=moto g play - 2024\nro.product.vendor.device=fogona\nro.product.cpu.abi=arm64-v8a\n"),
		DT: DT{Model: "fogona", SoC: "qcom,khaje", Compat: []string{"mot.fogona"}, Panels: []Panel{
			{Name: "a", W: 720, H: 1600}, {Name: "b", W: 720, H: 1600}}},
		Partitions: []string{"super", "vbmeta_a"}, SectorSize: 4096,
		Boot: Boot{HeaderVersion: 4, PageSize: 4096, Kernel: 0x8000, Ramdisk: 0x1000000, Tags: 0x100, DTB: 0x1f00000},
	}
	out := Render(Deviceinfo(p))
	for _, want := range []string{
		`deviceinfo_name="Motorola Moto G Play 2024"`,
		`deviceinfo_codename="motorola-fogona"`,
		`deviceinfo_screen_width="720"`,
		`deviceinfo_flash_fastboot_partition_rootfs="super"`,
		`deviceinfo_rootfs_image_sector_size="4096"`,
		`deviceinfo_flash_offset_dtb="0x01f00000"`,
		"# TODO deviceinfo_year",
		"# TODO deviceinfo_dtb",
		"# TODO deviceinfo_chassis",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestDeviceinfoPanelsDisagree(t *testing.T) {
	p := Package{DT: DT{Panels: []Panel{{Name: "a", W: 720, H: 1600}, {Name: "b", W: 1080, H: 2400}}}}
	out := Render(Deviceinfo(p))
	if strings.Contains(out, `deviceinfo_screen_width=`) || !strings.Contains(out, "# TODO deviceinfo_screen_width") {
		t.Errorf("disagreeing panels must not set a size:\n%s", out)
	}
}
