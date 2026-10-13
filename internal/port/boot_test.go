package port

import (
	"encoding/binary"
	"testing"
)

func TestParseBootReadsAHeaderV2BootImage(t *testing.T) {
	b := make([]byte, 4096)
	copy(b, "ANDROID!")
	le := binary.LittleEndian
	le.PutUint32(b[12:], 0x8000)    // kernel_addr
	le.PutUint32(b[20:], 0x1000000) // ramdisk_addr
	le.PutUint32(b[32:], 0x100)     // tags_addr
	le.PutUint32(b[36:], 4096)      // page size
	le.PutUint32(b[40:], 2)         // header version
	copy(b[64:], "console=ttyMSM0")
	le.PutUint64(b[1652:], 0x1f00000) // dtb_addr
	got, err := ParseBoot(b)
	if err != nil {
		t.Fatal(err)
	}
	want := Boot{HeaderVersion: 2, PageSize: 4096, Kernel: 0x8000, Ramdisk: 0x1000000, Tags: 0x100, DTB: 0x1f00000, Cmdline: "console=ttyMSM0", Source: "boot"}
	if got != want {
		t.Errorf("got %+v want %+v", got, want)
	}
	if _, err := ParseBoot(b[:100]); err == nil {
		t.Error("a short image should not parse")
	}
}

func TestPanelFileNameHasNoSpaces(t *testing.T) {
	if got := PanelFileName("hx83102p boe 2k video mode dsi panel"); got != "panel-hx83102p-boe-2k-video-mode-dsi-panel.c" {
		t.Errorf("got %q", got)
	}
	if got := PanelFileName("mipi_mot_vid_tm_icnl9916c_hd_720_1600"); got != "panel-mipi-mot-vid-tm-icnl9916c-hd-720-1600.c" {
		t.Errorf("got %q", got)
	}
}
