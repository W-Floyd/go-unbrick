package port

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
)

func TestKnownTreeKeysAddsTheBestDtsiNames(t *testing.T) {
	got := strings.Join(KnownTreeKeys("qcom,khaje", []string{"arch/arm64/boot/dts/qcom/sm6225.dtsi", "arch/arm64/boot/dts/qcom/sm6225.dtsi"}), " ")
	if got != "qcom,khaje qcom,sm6225" {
		t.Errorf("keys %q: the stock codename and the matched dtsi's name, each once", got)
	}
	if got := strings.Join(KnownTreeKeys("mediatek,MT6768", nil), " "); got != "mediatek,mt6768" {
		t.Errorf("keys %q", got)
	}
}

func TestKnownTreeValueAndSection(t *testing.T) {
	a := catalog.KnownTree{URL: "https://github.com/mt6768-mainline/linux", Ref: "cleanup", Notes: "Mainline fork", Pinned: "abc123"}
	b := catalog.KnownTree{URL: "https://gitlab.com/x/linux"}
	if KnownTreeValue(a) != "https://github.com/mt6768-mainline/linux#cleanup" || KnownTreeValue(b) != "https://gitlab.com/x/linux" {
		t.Errorf("values %q %q", KnownTreeValue(a), KnownTreeValue(b))
	}
	sec := KnownTreesSection([]catalog.KnownTree{a, b}, "mediatek,MT6768", []TreeChoice{{Name: KnownTreeValue(a)}})
	for _, want := range []string{"## Known kernel trees", "--kernel-tree known", "| https://github.com/mt6768-mainline/linux | cleanup | abc123 | Mainline fork | used |", "| https://gitlab.com/x/linux | default | — |"} {
		if !strings.Contains(sec, want) {
			t.Errorf("section lacks %q:\n%s", want, sec)
		}
	}
	if KnownTreesSection(nil, "x", nil) != "" {
		t.Error("none known, no section")
	}
}
