package port

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

const refSrc = `
/* a comment with { braces } that must not count */
&i2c2 {
	status = "okay";

	// line comment {
	fuel_gauge: fuel-gauge@64 {
		compatible = "cellwise,cw221X";
		reg = <0x64>;
		sub {
			compatible = "not,this";
		};
	};

	amp@34 {
		compatible = "awinic,aw88261", "fallback,x";
		reg = <0x34>;
	};
};

&spi0 {
	touch@0 { compatible = "chipone,icnl9916"; reg = <0>; };
};

&i2c9 { };
`

func TestParseReferenceDTS(t *testing.T) {
	got := ParseReferenceDTS(refSrc)
	type want struct {
		bus    string
		addr   uint32
		compat string
	}
	exp := []want{{"i2c2", 0x64, "cellwise,cw221X"}, {"i2c2", 0x34, "awinic,aw88261"}, {"spi0", 0, "chipone,icnl9916"}}
	if len(got) != len(exp) {
		t.Fatalf("got %+v", got)
	}
	for i, e := range exp {
		if got[i].Bus != e.bus || got[i].Addr != e.addr || got[i].Compatible[0] != e.compat {
			t.Errorf("node %d = %+v, want %+v", i, got[i], e)
		}
	}
	if len(got[1].Compatible) != 2 {
		t.Errorf("a compatible list keeps every entry: %v", got[1].Compatible)
	}
}

func TestCompareDTSAgreementDifferenceAndMissing(t *testing.T) {
	part := func(compat, bus string, addr byte) Part {
		n := &fdt.Node{Name: "x", Props: map[string][]byte{"reg": {0, 0, 0, addr}}, Keys: []string{"reg"}}
		return Part{Compatible: compat, Bus: bus, Node: "x@1", Source: n}
	}
	p := Package{
		DT: DT{Parts: []Part{
			part("cellwise,cw2217", "qupv3_se2_i2c", 0x64), // reference has the sibling cw221X
			part("awinic,aw88261", "qupv3_se2_i2c", 0x34),  // exact
			part("acme,other", "qupv3_se2_i2c", 0x70),      // same slot... not present
			part("ti,bq2589x-1", "qupv3_se1_i2c", 0x6a),    // a different part in the reference
		}},
		Mainline: map[string]*MainlineDriver{
			"cellwise,cw2217": {Similar: []string{"cellwise,cw221X (drivers/power/supply/cw221x_battery.c)"}},
		},
	}
	ref := refSrc + `
&i2c1 {
	charger@6a {
		compatible = "southchip,sc89890h";
		reg = <0x6a>;
	};
};

&cci_i2c0 {
	cam@56 {
		compatible = "samsung,s5kjns";
		reg = <0x56>;
	};
};`
	out := CompareDTS(p, ref)
	for _, want := range []string{
		"1 are the same slot with a different part",
		"2 agree", // cw2217 via its sibling, and the exact aw88261
		"| i2c2@70 | `acme,other` | no node at this address in the reference |",
		"reference has `southchip,sc89890h`",
		"cci_i2c0@56",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestMainlineBus(t *testing.T) {
	for in, want := range map[string]string{"qupv3_se1_i2c": "i2c1", "qupv3_se0_spi": "spi0", "QUPV3_SE2_I2C": "i2c2"} {
		if got, ok := MainlineBus(in); !ok || got != want {
			t.Errorf("%s -> %q %v, want %q", in, got, ok, want)
		}
	}
	if _, ok := MainlineBus("cam_cci0"); ok {
		t.Error("a camera control interface is not a serial engine")
	}
}
