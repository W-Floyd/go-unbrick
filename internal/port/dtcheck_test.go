package port

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckDTSBlamesTheBoardOnlyForWhatItAdds(t *testing.T) {
	if _, err := exec.LookPath("dtc"); err != nil {
		t.Skip("dtc is not installed")
	}
	if _, err := exec.LookPath("clang"); err != nil {
		if _, err := exec.LookPath("gcc"); err != nil {
			t.Skip("no C preprocessor")
		}
	}
	tree := t.TempDir()
	dts := filepath.Join(tree, "arch", "arm64", "boot", "dts", "qcom")
	if err := os.MkdirAll(dts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tree, "include"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The SoC dtsi refers to a label it leaves to the board (an error on its own).
	write := func(path, text string) {
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dts, "soc.dtsi"), "/ { soc { clock-controller { clocks = <&xo_board>; }; }; };\n")

	out := t.TempDir()
	good := filepath.Join(out, "good.dts")
	write(good, "/dts-v1/;\n#include \"soc.dtsi\"\n/ { xo_board: xo { compatible = \"fixed-clock\"; #clock-cells = <0>; clock-frequency = <19200000>; }; };\n")
	bad := filepath.Join(out, "bad.dts")
	write(bad, "/dts-v1/;\n#include \"soc.dtsi\"\n/ { xo_board: xo { compatible = \"fixed-clock\"; #clock-cells = <0>; clock-frequency = <19200000>; }; node { x = <&nowhere>; }; };\n")

	r, err := CheckDTS(tree, good, "arch/arm64/boot/dts/qcom/soc.dtsi")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Errors) != 0 || r.BaselineErrors == 0 {
		t.Errorf("a board that supplies the label adds no errors, though the dtsi alone has some: %+v", r)
	}
	r, err = CheckDTS(tree, bad, "arch/arm64/boot/dts/qcom/soc.dtsi")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "nowhere") {
		t.Errorf("a reference to a missing label is the board's error: %+v", r)
	}
}
