package nura

import "strings"

// ParseProps reads build.prop key=value lines.
func ParseProps(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && !strings.HasPrefix(k, "#") {
			m[k] = v
		}
	}
	return m
}

// ParseFstab reads a first-stage fstab. A mount marked `logical` lives in
// super; anything else is a block device by name.
func ParseFstab(s string) []FstabEntry {
	var out []FstabEntry
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 || strings.HasPrefix(f[0], "#") {
			continue
		}
		e := FstabEntry{Source: strings.TrimPrefix(f[0], "/dev/block/bootdevice/by-name/"), Mount: f[1], FS: f[2]}
		for _, flag := range strings.Split(f[4], ",") {
			e.Logical = e.Logical || flag == "logical"
		}
		out = append(out, e)
	}
	return out
}
