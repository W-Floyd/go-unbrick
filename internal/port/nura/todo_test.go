package nura

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/port"
)

// bareTodos returns the lines that mark a decision with a TODO not written
// "TODO: ". Prose about the convention and the TODO_function placeholder are
// not markers.
func bareTodos(text string) []string {
	var bad []string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "marked TODO") {
			continue
		}
		for i := 0; i+4 <= len(line); i++ {
			if line[i:i+4] != "TODO" {
				continue
			}
			if next := line[i+4:]; !strings.HasPrefix(next, ": ") && !strings.HasPrefix(next, "_") && !strings.HasPrefix(next, ",") {
				bad = append(bad, strings.TrimSpace(line))
				break
			}
		}
	}
	return bad
}

func TestGeneratedPackagingMarksDecisionsAsTODOColon(t *testing.T) {
	// Everything unknown: no panels, no 64-bit ABI, no catalog.
	p := port.Package{Props: map[string]string{"ro.product.vendor.manufacturer": "motorola", "ro.product.vendor.device": "fogona"}}
	lines := Deviceinfo(p, false)
	deviceinfo := []byte(Render(lines))
	fw, _ := firmwarePackage(p, port.Options{}, configFrom(nil), []string{"vendor_a:etc/x.ini"})
	for name, text := range map[string]string{
		"deviceinfo":        string(deviceinfo),
		"APKBUILD":          apkbuild(p, configFrom(nil), deviceinfo, lines, nil, ""),
		"firmware APKBUILD": string(fw["firmware-motorola-fogona/APKBUILD"]),
	} {
		if bad := bareTodos(text); len(bad) > 0 {
			t.Errorf("%s has bare TODO markers: %q", name, bad)
		}
		if !strings.Contains(text, "TODO: ") {
			t.Errorf("%s has no TODO at all, so the check proves nothing", name)
		}
	}
}
