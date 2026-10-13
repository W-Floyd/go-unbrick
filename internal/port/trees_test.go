package port

import (
	"path/filepath"
	"strings"
	"testing"
)

func twoTrees(t *testing.T) (mainline, fork string) {
	t.Helper()
	mainline, fork = t.TempDir(), t.TempDir()
	writeFiles(t, mainline, map[string]string{
		"arch/arm64/boot/dts/mediatek/mt8183.dtsi":    "/ {\n\tsoc {\n\t\tserial@11002000 {\n\t\t};\n\t\ti2c@11007000 {\n\t\t};\n\t\ti2c@11008000 {\n\t\t};\n\t};\n};\n",
		"drivers/gpu/drm/panel/panel-himax-hx83102.c": "static const struct of_device_id a[] = { { .compatible = \"himax,hx83102\" } };\n",
	})
	writeFiles(t, fork, map[string]string{
		"arch/arm64/boot/dts/mediatek/mt6768.dtsi": "// mediatek,mt6768\n/ {\n\tsoc {\n\t\tserial@11002000 {\n\t\t};\n\t\ti2c@11007000 {\n\t\t};\n\t};\n};\n",
		"drivers/media/i2c/gc08a3.c":               "int x;\n",
		"drivers/power/supply/sgm41511.c":          "static const struct of_device_id a[] = { { .compatible = \"sgm,sgm41511\" } };\n",
	})
	return mainline, fork
}

func TestMatchTreesPicksTheTreeWhoseDtsiBestFitsAndNamesTheSoC(t *testing.T) {
	mainline, fork := twoTrees(t)
	stock := map[string]bool{"11002000": true, "11007000": true, "11008000": true, "14000000": true}

	// Scores alone prefer the bigger mainline file (3 of 4 shared against 2).
	ms, target, choices, err := MatchTrees([]string{mainline, fork}, nil, stock, "")
	if err != nil || target != mainline || len(choices) != 2 {
		t.Fatalf("by score: target %q choices %+v err %v", target, choices, err)
	}
	if !filepath.IsAbs(ms[0].Root) || ms[0].Root != mainline {
		t.Errorf("a match carries its tree: %+v", ms[0])
	}

	// Naming the SoC lets the fork win, though it covers less.
	for i := 0; i < 8; i++ { // enough overlap to count as naming it
		stock[strings.Repeat("2", 1)+string(rune('a'+i))+"000000"] = true
	}
	writeFiles(t, fork, map[string]string{"arch/arm64/boot/dts/mediatek/mt6768.dtsi": "// mediatek,mt6768\n/ {\n\tsoc {\n" + manyNodes(stock) + "\t};\n};\n"})
	_, target, choices, err = MatchTrees([]string{mainline, fork}, nil, stock, "mediatek,MT6768")
	if err != nil || target != fork {
		t.Fatalf("by name: target %q err %v choices %+v", target, err, choices)
	}
	var forkChoice TreeChoice
	for _, c := range choices {
		if c.Root == fork {
			forkChoice = c
		}
	}
	if !forkChoice.Chosen || !forkChoice.Names || !forkChoice.Has {
		t.Errorf("fork choice %+v", forkChoice)
	}
	sec := TreesSection(choices, "mediatek,MT6768")
	if !strings.Contains(sec, "**chosen**") || !strings.Contains(sec, "mt6768.dtsi") || !strings.Contains(sec, "yes") {
		t.Errorf("section:\n%s", sec)
	}
	if TreesSection(choices[:1], "x") != "" {
		t.Error("one tree needs no section")
	}
	if _, _, _, err := MatchTrees([]string{filepath.Join(t.TempDir(), "nope")}, nil, stock, ""); err == nil {
		t.Error("a path that is not a kernel tree is an error")
	}
}

func manyNodes(stock map[string]bool) string {
	var b strings.Builder
	for a := range stock {
		b.WriteString("\t\tnode@" + a + " {\n\t\t};\n")
	}
	return b.String()
}

func TestOtherTreesFillInDriversTheTargetLacks(t *testing.T) {
	mainline, fork := twoTrees(t)
	// The target is the mainline tree; the fork has the sensor and the charger.
	got := FindDriversInTrees(mainline, []string{mainline, fork}, []string{"gc08a3_mipi_raw", "hx83102p_wxga", "s5k4h7_mipi_raw"})
	label := filepath.Base(fork)
	if got["gc08a3_mipi_raw"][0] != label+":drivers/media/i2c/gc08a3.c" {
		t.Errorf("a driver only the other tree has carries its name: %v", got)
	}
	if got["hx83102p_wxga"][0] != "drivers/gpu/drm/panel/panel-himax-hx83102.c" {
		t.Errorf("the target's own driver is unprefixed: %v", got)
	}
	if len(got["s5k4h7_mipi_raw"]) != 0 {
		t.Errorf("neither tree has it: %v", got)
	}

	md, err := ScanKernelTrees(mainline, []string{mainline, fork}, []string{"himax,hx83102", "sgm,sgm41511", "no,such"})
	if err != nil {
		t.Fatal(err)
	}
	if len(md["himax,hx83102"].Sources) != 1 || strings.Contains(md["himax,hx83102"].Sources[0], ":") {
		t.Errorf("the target's own: %+v", md["himax,hx83102"])
	}
	if s := md["sgm,sgm41511"].Sources; len(s) != 1 || s[0] != label+":drivers/power/supply/sgm41511.c" {
		t.Errorf("found in the other tree: %+v", md["sgm,sgm41511"])
	}
	if m := md["no,such"]; len(m.Sources) != 0 || len(m.Bindings) != 0 {
		t.Errorf("neither: %+v", m)
	}
}
