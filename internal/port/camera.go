package port

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Qualcomm's camera stack takes one sensor-module file per fitted module,
// com.qti.sensormodule.<sensor>_<maker>_<facing>_<rev>.bin, and a matching
// tuned file. The package ships one per option the board may be built with, so
// they name the sensors and their second sources without any device tree.

// CameraModule is one sensor-module option.
type CameraModule struct {
	Sensor string // "ov13b10"
	Maker  string // the module maker, "oflim"
	Facing string // "back", "front"
	Rev    string // "i", "ii"
	File   string // where the module file is
	Tuned  bool   // a tuned file for it is shipped too
}

// CameraModules finds the sensor-module files among a partition's file paths.
func CameraModules(files []string) []CameraModule {
	const prefix = "com.qti.sensormodule."
	have := map[string]bool{}
	for _, f := range files {
		have[path.Base(f)] = true
	}
	seen := map[string]bool{}
	var out []CameraModule
	for _, f := range files {
		base := path.Base(f)
		name, ok := strings.CutPrefix(base, prefix)
		if !ok || !strings.HasSuffix(name, ".bin") || seen[base] {
			continue
		}
		seen[base] = true
		stem := strings.TrimSuffix(name, ".bin")
		m := CameraModule{File: f, Tuned: have["com.qti.tuned."+stem+".bin"]}
		parts := strings.Split(stem, "_")
		if n := len(parts); n >= 4 && facings[parts[n-2]] {
			m.Sensor, m.Maker = parts[0], strings.Join(parts[1:n-2], "_")
			m.Facing, m.Rev = parts[n-2], parts[n-1]
		} else {
			// Another naming (Motorola's "mot_<codename>_<sensor>_<maker>"): the
			// name is all that is known, so it is shown as it is.
			m.Sensor = stem
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Facing != b.Facing {
			return a.Facing < b.Facing
		}
		if a.Sensor != b.Sensor {
			return a.Sensor < b.Sensor
		}
		return a.Maker+a.Rev < b.Maker+b.Rev
	})
	return out
}

// CameraSection is the report's account of the camera modules.
func CameraSection(mods []CameraModule) string {
	if len(mods) == 0 {
		return ""
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## Cameras\n")
	w("The sensor modules the stock camera stack can drive, from its module files. Each facing is built with one of its sensors; a unit's own is not in the package (the camera HAL logs it on a running device).\n")
	w("| facing | sensor | maker | rev | tuned file | module file |")
	w("|---|---|---|---|---|---|")
	for _, m := range mods {
		tuned := "no"
		if m.Tuned {
			tuned = "yes"
		}
		w("| %s | %s | %s | %s | %s | %s |", m.Facing, m.Sensor, m.Maker, m.Rev, tuned, m.File)
	}
	return b.String()
}

// facings are the words a module name uses for where the camera is.
var facings = map[string]bool{"back": true, "front": true, "rear": true, "main": true, "aux": true, "wide": true, "macro": true, "depth": true, "tele": true}
