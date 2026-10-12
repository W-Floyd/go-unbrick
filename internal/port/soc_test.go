package port

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnitAddr(t *testing.T) {
	for in, want := range map[string]string{"serial@4A84000": "4a84000", "i2c@04a84000": "4a84000", "sgm7220@47": "", "memory": "", "x@zzzzzz": ""} {
		got, ok := unitAddr(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q -> %q %v, want %q", in, got, ok, want)
		}
	}
}

func TestCollectAddrsReadsSymbolsAndPeripheralAddresses(t *testing.T) {
	root := node("", nil,
		node("soc", nil,
			node("geniqup@4ac0000", nil,
				node("i2c@4a84000", nil),
				node("sgm@47", nil)),
		),
		node("__symbols__", map[string]string{"qupv3_se1_i2c": "/soc/geniqup@4ac0000/i2c@4a84000\x00"}),
	)
	var dt DT
	dt.Symbols, dt.UnitAddrs = map[string]string{}, map[string]bool{}
	collectAddrs(root, &dt)
	if !dt.UnitAddrs["4ac0000"] || !dt.UnitAddrs["4a84000"] || dt.UnitAddrs["47"] {
		t.Errorf("addresses %v (a client address is not a register address)", dt.UnitAddrs)
	}
	if dt.Symbols["qupv3_se1_i2c"] != "/soc/geniqup@4ac0000/i2c@4a84000" {
		t.Errorf("symbols %v", dt.Symbols)
	}
}

func TestFindSoCDTSIRanksByRegisterMap(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, "arch/arm64/boot/dts/qcom", name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	write("close.dtsi", "a: serial@1000000 {};\nb: i2c@2000000 {};\nc: usb@3000000 {};\nd: x@4000000 {};")
	write("far.dtsi", "a: serial@1000000 {};\nb: pci@9000000 {};\nc: gpu@a000000 {};")
	write("none.dtsi", "a: pci@9000000 {};")
	write("board.dts", "x: serial@1000000 {};") // a board file is not a SoC include
	stock := map[string]bool{"1000000": true, "2000000": true, "3000000": true, "5000000": true}
	got, err := FindSoCDTSI(dir, stock)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || filepath.Base(got[0].File) != "close.dtsi" || filepath.Base(got[1].File) != "far.dtsi" {
		t.Fatalf("ranking %+v (a dtsi sharing nothing is dropped, a .dts is not an include)", got)
	}
	if got[0].Shared != 3 || got[0].Stock != 4 || got[0].Tree != 4 || got[0].Score <= got[1].Score {
		t.Errorf("scores %+v", got)
	}
}

func TestBusLabelsMatchByKindAndAddress(t *testing.T) {
	// The serial engine at 4a84000 is both i2c1 and spi1 in a SoC dtsi.
	dtsi := `
		i2c1: i2c@4a84000 {
			status = "disabled";
		};

		spi1: spi@4a84000 {
			status = "disabled";
		};

		i2c2: i2c@4a88000 {
		};
`
	dt := DT{Symbols: map[string]string{
		"qupv3_se1_i2c": "/soc/geniqup@4ac0000/i2c@4a84000",
		"qupv3_se1_spi": "/soc/geniqup@4ac0000/spi@4a84000",
		"qupv3_se2_i2c": "/soc/geniqup@4ac0000/i2c@04a88000",
		"qupv3_se9_i2c": "/soc/geniqup@4ac0000/i2c@4a9c000", // not in the dtsi
		"tlmm":          "/soc/pinctrl@500000",
	}}
	got := BusLabels(dt, dtsi)
	want := map[string]string{"qupv3_se1_i2c": "i2c1", "qupv3_se1_spi": "spi1", "qupv3_se2_i2c": "i2c2"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s -> %q, want %q (the kind must pick between i2c1 and spi1)", k, got[k], v)
		}
	}
}

func TestBusLabelFallsBackToTheAssumption(t *testing.T) {
	p := Package{BusLabels: map[string]string{"qupv3_se1_i2c": "i2c1"}}
	if l, verified, ok := p.busLabel("qupv3_se1_i2c"); l != "i2c1" || !verified || !ok {
		t.Errorf("verified: %q %v %v", l, verified, ok)
	}
	if l, verified, ok := p.busLabel("qupv3_se2_i2c"); l != "i2c2" || verified || !ok {
		t.Errorf("assumed: %q %v %v", l, verified, ok)
	}
}

func TestBoardDTS(t *testing.T) {
	p := Package{
		Props: map[string]string{"ro.product.vendor.manufacturer": "motorola", "ro.product.vendor.device": "fogona", "ro.product.vendor.model": "moto g play - 2024"},
		SoC:   []SoCMatch{{File: "arch/arm64/boot/dts/qcom/sm6225.dtsi", Score: 0.47}, {File: "arch/arm64/boot/dts/qcom/sm6115.dtsi", Score: 0.44}},
	}
	out := BoardDTS(p)
	for _, want := range []string{
		`#include "sm6225.dtsi"`,
		`#include "motorola-fogona-peripherals.dtsi"`,
		`compatible = "motorola,fogona", "qcom,sm6225";`,
		"the next closest SoC is sm6115",
		"TODO: chassis-type",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if out := BoardDTS(Package{Props: p.Props}); !strings.Contains(out, "TODO: the SoC include") {
		t.Errorf("without a tree the SoC include is a TODO:\n%s", out)
	}
}
