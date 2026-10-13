package port

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindSoCDTSISearchesEveryVendorDirectory(t *testing.T) {
	root := t.TempDir()
	for dir, files := range map[string]map[string]string{
		"qcom":     {"sm6115.dtsi": "/ { soc { uart@4a90000 {}; i2c@4a84000 {}; }; };"},
		"mediatek": {"mt8183.dtsi": "/ { soc { i2c@11007000 {}; i2c@11008000 {}; uart@11002000 {}; }; };", "board.dts": "i2c@11007000 {};"},
	} {
		d := filepath.Join(root, "arch", "arm64", "boot", "dts", dir)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, text := range files {
			if err := os.WriteFile(filepath.Join(d, name), []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	stock := map[string]bool{"11007000": true, "11008000": true, "11002000": true, "13000000": true}
	ms, err := FindSoCDTSI(root, stock)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].File != "arch/arm64/boot/dts/mediatek/mt8183.dtsi" || ms[0].Shared != 3 {
		t.Errorf("got %+v (only the dtsi with shared addresses, from whichever vendor)", ms)
	}
}
