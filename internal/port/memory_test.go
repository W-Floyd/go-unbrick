package port

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

func region(name string, addr, size uint32) *fdt.Node {
	return &fdt.Node{Name: name, Props: map[string][]byte{"reg": cells(0, addr, 0, size), "no-map": nil}, Keys: []string{"reg", "no-map"}}
}

func TestReadRegionsFromBaseAndOverlay(t *testing.T) {
	pool := &fdt.Node{Name: "user_contig_region", Props: map[string][]byte{"size": cells(0, 0x1000000), "compatible": []byte("shared-dma-pool\x00")}, Keys: []string{"size", "compatible"}}
	base := node("", nil, node("reserved-memory", nil, region("hyp_region@45700000", 0x45700000, 0x600000), pool))
	overlay := node("", nil,
		node("fragment@4", nil, node("__overlay__", nil, region("ramoops_region@af000000", 0xaf000000, 0xbf800))),
		node("fragment@5", nil, node("__overlay__", nil, region("not_memory@1000", 0x1000, 0x10))),
		node("__fixups__", map[string]string{
			"reserved_memory": "/fragment@4:target:0\x00",
			"soc":             "/fragment@5:target:0\x00",
		}),
	)
	got := readRegions([]*fdt.Node{base}, []*fdt.Node{overlay})
	byName := map[string]Region{}
	for _, r := range got {
		byName[r.Name] = r
	}
	if r := byName["hyp_region"]; !r.Fixed || r.Addr != 0x45700000 || r.Size != 0x600000 || !r.NoMap || r.From != "base" {
		t.Errorf("hyp: %+v", r)
	}
	if r := byName["ramoops_region"]; r.Addr != 0xaf000000 || r.From != "overlay" {
		t.Errorf("ramoops from an overlay fragment: %+v", r)
	}
	if r := byName["user_contig_region"]; r.Fixed || r.Size != 0x1000000 || r.Compat != "shared-dma-pool" {
		t.Errorf("a pool has a size and no address: %+v", r)
	}
	if _, ok := byName["not_memory"]; ok {
		t.Error("a fragment that does not target reserved-memory must not count")
	}
}

const socSrc = `
/ {
	reserved_memory: reserved-memory {
		#address-cells = <2>;
		ranges;

		hyp_mem: memory@45700000 {
			reg = <0x0 0x45700000 0x0 0x600000>;
			no-map;
		};

		/* cdsp_sec: memory@46200000 { reg = <0x0 0x46200000 0x0 0x1e00000>; }; */
		smem_mem: memory@46000000 {
			compatible = "qcom,smem";
			reg = <0x0 0x46000000 0x0 0x200000>;
			no-map;
		};
	};

	soc {
		not-a-region@1000 {
			reg = <0x0 0x1000 0x0 0x10>;
		};
	};
};
`

func TestParseDTSRegions(t *testing.T) {
	got := ParseDTSRegions(socSrc)
	if len(got) != 2 {
		t.Fatalf("got %+v (a commented-out region and nodes outside the block must not count)", got)
	}
	if got[0].Addr != 0x45700000 || got[0].Size != 0x600000 || !got[0].NoMap || got[1].Compat != "qcom,smem" {
		t.Errorf("parsed %+v", got)
	}
}

func TestBoardRegionsAreTheOnesTheSoCDtsiLacks(t *testing.T) {
	stock := []Region{
		{Name: "hyp_region", Addr: 0x45700000, Size: 0x600000, Fixed: true},
		{Name: "ramoops_region", Addr: 0xaf000000, Size: 0xbf800, Fixed: true},
		{Name: "same_start_other_size", Addr: 0x46000000, Size: 0x100000, Fixed: true},
		{Name: "pool", Size: 0x1000000},
	}
	board, inSoC, conflicts := ClassifyRegions(stock, ParseDTSRegions(socSrc))
	names := func(rs []Region) string {
		var n []string
		for _, r := range rs {
			n = append(n, r.Name)
		}
		return strings.Join(n, " ")
	}
	if names(inSoC) != "hyp_region" || names(board) != "ramoops_region" || names(conflicts) != "same_start_other_size" {
		t.Errorf("in SoC %q, board %q, conflicts %q (a region is the SoC's at the same address and size; one overlapping it otherwise is a conflict, not a second node; a pool has no address to match)",
			names(inSoC), names(board), names(conflicts))
	}
	if b, _ := BoardRegions(stock, ParseDTSRegions(socSrc)); names(b) != "ramoops_region" {
		t.Errorf("BoardRegions must leave conflicts out: %q", names(b))
	}
}

func TestClassifyRegionsRejectsTwoStockRegionsOverOneRange(t *testing.T) {
	stock := []Region{
		{Name: "tz_stat_region", Addr: 0x60000000, Size: 0x100000, Fixed: true},
		{Name: "tz_removed_region", Addr: 0x60000000, Size: 0x80000, Fixed: true},
	}
	board, _, conflicts := ClassifyRegions(stock, nil)
	if len(board) != 1 || board[0].Name != "tz_stat_region" || len(conflicts) != 1 {
		t.Errorf("board %+v conflicts %+v", board, conflicts)
	}
}

func TestBoardDTSAndReportCarryTheBoardRegions(t *testing.T) {
	p := Package{
		Props:      map[string]string{"ro.product.vendor.manufacturer": "motorola", "ro.product.vendor.device": "fogona"},
		SoC:        []SoCMatch{{File: "arch/arm64/boot/dts/qcom/sm6225.dtsi", Score: 0.5}},
		SoCRegions: ParseDTSRegions(socSrc),
		DT: DT{Reserved: []Region{
			{Name: "hyp_region", Addr: 0x45700000, Size: 0x600000, Fixed: true, NoMap: true},
			{Name: "ramoops_region", Addr: 0xaf000000, Size: 0xbf800, Fixed: true, NoMap: true, Compat: "ramoops", From: "overlay"},
		}},
	}
	dts := BoardDTS(p)
	for _, want := range []string{"reserved-memory {", "ramoops-region@af000000 {", `compatible = "ramoops";`, "reg = <0x0 0xaf000000 0x0 0xbf800>;", "no-map;"} {
		if !strings.Contains(dts, want) {
			t.Errorf("board dts lacks %q:\n%s", want, dts)
		}
	}
	if strings.Contains(dts, "hyp-region") {
		t.Error("a region the SoC dtsi already has must not be repeated")
	}
	rep := MemorySection(p)
	if !strings.Contains(rep, "1 are already in the SoC dtsi") || !strings.Contains(rep, "**1 are not**") {
		t.Errorf("report:\n%s", rep)
	}
	// Without a tree there is nothing to compare against.
	p.SoCRegions = nil
	if rep := MemorySection(p); !strings.Contains(rep, "--kernel-tree") {
		t.Errorf("no-tree report:\n%s", rep)
	}
}

func TestCompareDTSChecksBoardRegionsAgainstTheReference(t *testing.T) {
	p := Package{
		SoCRegions: ParseDTSRegions(socSrc),
		DT: DT{Reserved: []Region{
			{Name: "ramoops_region", Addr: 0xaf000000, Size: 0xbf800, Fixed: true},
			{Name: "tzlog_dump", Addr: 0xaef9e000, Size: 0x30000, Fixed: true},
		}},
	}
	ref := `
/ {
	reserved-memory {
		ramoops@af000000 {
			compatible = "ramoops";
			reg = <0x0 0xaf000000 0x0 0xbf800>;
			no-map;
		};
	};
};
`
	out := CompareDTS(p, ref)
	if !strings.Contains(out, "1 of 2 are in the reference") || !strings.Contains(out, "tzlog_dump@aef9e000") {
		t.Errorf("got:\n%s", out)
	}
}
