package port

import "testing"

const liveDevices = "/sys/bus/i2c/devices\t1-0064\t\t../../bus/i2c/drivers/cw2217\t../../firmware/devicetree/base/soc/qcom,qupv3_0_geni_se@4ac0000/i2c@4a88000/cw2217@64\n" +
	"/sys/bus/i2c/devices\t0-003b\t\t\t../../firmware/devicetree/base/soc/qcom,qupv3_0_geni_se@4ac0000/i2c@4a84000/sgm4154x@3B\n"

func TestParseLiveDevices(t *testing.T) {
	d := ParseLiveDevices(liveDevices)
	if len(d) != 2 {
		t.Fatalf("got %d devices", len(d))
	}
	if d[0].Kind != "i2c" || d[0].Driver != "cw2217" || d[0].Node != "cw2217" || d[0].Addr != "64" || d[0].ParentAddr != "4a88000" {
		t.Errorf("bound: %+v", d[0])
	}
	if d[1].Driver != "" || d[1].Addr != "3b" {
		t.Errorf("unbound, address folded to lower case: %+v", d[1])
	}
}

func TestEvalMMIStatus(t *testing.T) {
	chosen := map[string]string{"mmi,panel_name": "tm_icnl9916c_720x1600_652_vid"}
	if ok, _, known := EvalMMIStatus([]string{"/chosen", "mmi,panel_name", "contains", "icnl9916c"}, chosen); !ok || !known {
		t.Error("contains should hold")
	}
	if ok, _, known := EvalMMIStatus([]string{"/chosen", "mmi,panel_name", "contains", "nt36528"}, chosen); ok || !known {
		t.Error("contains should fail")
	}
	if _, _, known := EvalMMIStatus([]string{"/other", "x", "y"}, chosen); known {
		t.Error("a non-/chosen condition is not evaluated")
	}
}

func TestFitFromBoundDrivers(t *testing.T) {
	p := Package{Live: &Live{Devices: ParseLiveDevices(liveDevices)},
		DT: DT{Symbols: map[string]string{"qupv3_se1_i2c": "/soc/qcom,qupv3_0_geni_se@4ac0000/i2c@4a88000"}}}
	n := node("x", nil)
	if f := p.Fit(Part{Source: n, Node: "cw2217@64", Bus: "qupv3_se1_i2c"}); f.State != Fitted {
		t.Errorf("bound client: %+v", f)
	}
	if f := p.Fit(Part{Source: n, Node: "sm5602@71", Bus: "qupv3_se1_i2c"}); f.State != NotFitted {
		t.Errorf("absent client: %+v", f)
	}
	if f := (Package{}).Fit(Part{Source: n}); f.State != FitUnknown {
		t.Errorf("no live data: %+v", f)
	}
}

func TestFittedPanel(t *testing.T) {
	p := Package{Live: &Live{Chosen: map[string]string{"mmi,panel_name": "tm_icnl9916c_720x1600_652_vid"}},
		DT: DT{Panels: []Panel{{Name: "mipi_mot_vid_boe_nt36528_hd_720_1600"}, {Name: "mipi_mot_vid_tm_icnl9916c_hd_720_1600"}}}}
	if n, ok := p.FittedPanel(); !ok || n != "mipi_mot_vid_tm_icnl9916c_hd_720_1600" {
		t.Errorf("got %q %v", n, ok)
	}
}

func TestNewLiveNotesWhatWasNotRead(t *testing.T) {
	// An unrooted shell: devices, but an empty chosen section.
	l := NewLive(map[string]string{"bus-devices": liveDevices, "chosen": ""}, "")
	if len(l.Devices) != 2 || l.HaveChosen || len(l.Notes) != 1 {
		t.Errorf("unrooted: %+v", l)
	}
	l = NewLive(map[string]string{"bus-devices": liveDevices, "chosen": "mmi,panel_name\ttm_icnl9916c_720x1600_652_vid\n"}, "")
	if !l.HaveChosen || l.Chosen["mmi,panel_name"] != "tm_icnl9916c_720x1600_652_vid" || len(l.Notes) != 0 {
		t.Errorf("rooted: %+v", l)
	}
}
