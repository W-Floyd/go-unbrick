package vendor

import (
	"path"
	"regexp"
	"strings"
)

// Xiaomi publishes a release's packages side by side, named from the device
// variant, build and Android version, plus a content hash (and, for the
// fastboot package, a build date) that only the publisher knows:
//
//	tapas_global_images_OS2.0.209.0.VMTMIXM_20260909.0000.00_15.0_global_2936b5ae03.tgz
//	tapas_global-ota_full-OS2.0.209.0.VMTMIXM-user-15.0-e4778deae7.zip
//
// The CDN does not list directories, so the other name is found only among
// known locations; failing that it is a hint with those parts marked.
var (
	xiaomiFastbootName = regexp.MustCompile(`^(.+)_images_([^_]+)_\d{8}\.\d{4}\.\d{2}_([0-9.]+)_[a-z]+_[0-9a-f]+\.tgz$`)
	xiaomiOTAName      = regexp.MustCompile(`^(.+)-ota_full-([^-]+)-user-([0-9.]+)-[0-9a-f]+\.zip$`)
)

// xiaomiHoles are the hint placeholders and what each stands for.
var xiaomiHoles = strings.NewReplacer(regexp.QuoteMeta("<hash>"), `[0-9a-f]+`, regexp.QuoteMeta("<date>"), `\d{8}\.\d{4}\.\d{2}`)

// Companions implements CompanionFinder.
func (xiaomi) Companions(p string, known []string) []Companion {
	dir, name := splitLocation(p)
	var c Companion
	switch m := xiaomiFastbootName.FindStringSubmatch(name); {
	case m != nil:
		c = Companion{What: "full OTA", Hint: m[1] + "-ota_full-" + m[2] + "-user-" + m[3] + "-<hash>.zip"}
	default:
		m = xiaomiOTAName.FindStringSubmatch(name)
		if m == nil {
			return nil
		}
		region := m[1][strings.LastIndex(m[1], "_")+1:]
		c = Companion{What: "fastboot package", Hint: m[1] + "_images_" + m[2] + "_<date>_" + m[3] + "_" + region + "_<hash>.tgz"}
	}
	want := regexp.MustCompile("^" + xiaomiHoles.Replace(regexp.QuoteMeta(c.Hint)) + "$")
	for _, k := range known {
		if _, kn := splitLocation(k); want.MatchString(kn) {
			c.URL = k
			break
		}
	}
	c.Hint = dir + c.Hint
	return []Companion{c}
}

// splitLocation splits a path or URL into the directory part, kept as given
// (with its trailing separator), and the file name, dropping any query.
func splitLocation(p string) (dir, name string) {
	if i := strings.IndexAny(p, "?#"); i >= 0 && strings.Contains(p, "://") {
		p = p[:i]
	}
	name = path.Base(strings.ReplaceAll(p, `\`, "/"))
	return p[:len(p)-len(name)], name
}
