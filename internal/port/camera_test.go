package port

import "testing"

func TestCameraModules(t *testing.T) {
	files := []string{
		"lib64/camera/com.qti.sensormodule.ov13b10_oflim_back_i.bin",
		"lib64/camera/com.qti.sensormodule.ov13b10_txd_back_ii.bin",
		"lib64/camera/com.qti.sensormodule.s5k4h7_qtech_front_i.bin",
		"lib64/camera/com.qti.tuned.ov13b10_oflim_back_i.bin",
		"lib64/camera/com.qti.tuned.default.bin",
		"lib/camera/com.qti.sensormodule.ov13b10_oflim_back_i.bin", // the 32-bit copy is the same module
		"lib64/camera/com.qti.sensormodule.bad.bin",
		"etc/other.xml",
	}
	got := CameraModules(files)
	if len(got) != 4 {
		t.Fatalf("got %d modules: %+v", len(got), got)
	}
	// A name in another scheme is kept whole, not split into invented columns.
	if got[0].Facing != "" || got[0].Sensor != "bad" || got[0].Maker != "" {
		t.Errorf("unparsed name: %+v", got[0])
	}
	var oflim *CameraModule
	for i := range got {
		if got[i].Maker == "oflim" && got[i].File == files[0] {
			oflim = &got[i]
		}
	}
	if oflim == nil || oflim.Sensor != "ov13b10" || oflim.Facing != "back" || oflim.Rev != "i" || !oflim.Tuned {
		t.Errorf("oflim: %+v", oflim)
	}
	if got[len(got)-1].Facing != "front" {
		t.Errorf("not sorted by facing: %+v", got)
	}
	for _, m := range got {
		if m.Maker == "txd" && m.Tuned {
			t.Error("txd has no tuned file")
		}
	}
}
