package port

import "testing"

func TestParseFstab(t *testing.T) {
	got := ParseFstab(`# c
system /system erofs ro wait,logical,first_stage_mount
/dev/block/bootdevice/by-name/modem /vendor/firmware_mnt ext4 ro wait,slotselect
`)
	if len(got) != 2 || !got[0].Logical || got[1].Logical || got[1].Source != "modem" {
		t.Errorf("got %+v", got)
	}
}
