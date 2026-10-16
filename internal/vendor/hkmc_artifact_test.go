package vendor

import "testing"

func TestHKMCArtifact(t *testing.T) {
	conb := make([]byte, 0x28)
	copy(conb, "ConB")
	conb = append(conb, 'M', 0, 'D', 0, '.', 0, 'x', 0, 0, 0)
	prnm := make([]byte, 0x30)
	copy(prnm, "PRNM")
	copy(prnm[0x10:], "2025/11/26 09:05")
	ffu := make([]byte, 0x30)
	copy(ffu[0x20:], "FQT00RD")
	for _, c := range []struct {
		name, label, detail string
		data                []byte
	}{
		{"x.bin", "navi config (ConB)", "MD.x", conb},
		{"x.npkg", "navi package (PRNM)", "built 2025/11/26 09:05", prnm},
		{"gps_module.bin", "Trimble GPS firmware (TRMB)", "", []byte("TRMB\x01")},
		{"ffu/ffu_sw.bin", "Micron FFU firmware", "FQT00RD", ffu},
	} {
		got, ok := hkmcArtifact(c.name, c.data)
		if !ok || got.Label != c.label || got.Detail != c.detail {
			t.Errorf("%s: got %+v ok=%v", c.name, got, ok)
		}
	}
	if _, ok := hkmcArtifact("ffu_sw.bin", make([]byte, 0x30)); ok {
		t.Error("ffu_sw.bin without FQT matched")
	}
}
