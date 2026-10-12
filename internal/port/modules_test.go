package port

import (
	"strings"
	"testing"
)

func TestParseModinfo(t *testing.T) {
	got := parseModinfo([]byte("description=A driver\x00alias=of:N*T*Cacme,thing\x00alias=i2c:thing\x00depends=a,b\x00\x00junk\x00"))
	want := [][2]string{{"description", "A driver"}, {"alias", "of:N*T*Cacme,thing"}, {"alias", "i2c:thing"}, {"depends", "a,b"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pair %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestReadModuleFindsFirmwareNamesInStrings(t *testing.T) {
	// Not an ELF, so only the string scan applies: a name shaped like a
	// firmware file, in whatever bytes the driver holds.
	m := ReadModule("lib/modules/touch_drv.ko", []byte("junk\x00touch_fw.bin\x00%s/other.mbn\x00plain text\x00"))
	if m.Name != "touch_drv" {
		t.Errorf("name %q", m.Name)
	}
	if got := strings.Join(m.Firmware, " "); !strings.Contains(got, "touch_fw.bin") || !strings.Contains(got, "other.mbn") {
		t.Errorf("firmware %q", got)
	}
}

func TestBindingByOFAndBusAlias(t *testing.T) {
	mods := []Module{
		{Name: "tddi", Aliases: []string{"of:N*T*Cchipone-tddi", "of:N*T*Cchipone-tddiC*"}},
		{Name: "amp", Aliases: []string{"i2c:aw882xx_smartpa"}},
		{Name: "spi_touch", Aliases: []string{"spi:ts"}},
		{Name: "other", Aliases: []string{"of:N*T*Cchipone-tddi-v2"}},
	}
	for compat, want := range map[string]string{
		"chipone-tddi":           "tddi",
		"awinic,aw882xx_smartpa": "amp", // the kernel drops the vendor prefix for I2C
		"acme,ts":                "spi_touch",
	} {
		if m, ok := Binding(mods, compat); !ok || m.Name != want {
			t.Errorf("%s -> %q (%v), want %s", compat, m.Name, ok, want)
		}
	}
	// A longer compatible must not be taken for a prefix match.
	if m, ok := Binding(mods, "chipone-tdd"); ok {
		t.Errorf("chipone-tdd bound to %q", m.Name)
	}
}
