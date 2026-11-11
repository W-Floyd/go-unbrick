package main

import (
	"fmt"
	"path/filepath"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// printNeusoftReport prints what a Neusoft-IVI update package (versions.dat
// + rootfs.dat, see internal/vendor/neusoft.go) says about itself, inline
// under the container the way printFjhdmiReport does for the Fujitsu Ten
// format. false (nothing printed) when kids has neither file.
func printNeusoftReport(kids []*carve.Node, indent string) bool {
	byName := make(map[string]*carve.Node, len(kids))
	for _, k := range kids {
		byName[filepath.Base(k.Name)] = k
	}
	printed := false
	versionsOK, rootfsOK := false, false
	if v, ok := byName["versions.dat"]; ok {
		if data, err := v.Bytes(); err == nil {
			info := vendor.ParseNeusoftVersions(data)
			versionsOK = info.AllVersion != "" || info.BootVersion != "" || info.SocVersion != "" || info.McuVersion != "" || info.CameraVersion != ""
			if info.AllVersion != "" {
				fmt.Printf("%sVersion:      %s\n", indent, info.AllVersion)
				printed = true
			}
			if info.BootVersion != "" || info.SocVersion != "" || info.McuVersion != "" || info.CameraVersion != "" {
				fmt.Printf("%sComponents:   boot=%s soc=%s mcu=%s camera=%s\n",
					indent, orDash(info.BootVersion), orDash(info.SocVersion), orDash(info.McuVersion), orDash(info.CameraVersion))
				printed = true
			}
		}
	}
	if r, ok := byName["rootfs.dat"]; ok {
		if data, err := r.Bytes(); err == nil {
			if m, ok := vendor.ParseNeusoftRootfsManifest(data); ok {
				rootfsOK = true
				var total int64
				for _, s := range m.PartSizes {
					total += s
				}
				fmt.Printf("%sRootfs:       %d part(s), %s total\n", indent, len(m.PartSizes), humanBytes(total))
				printed = true
			}
		}
	}
	// Both files matching this format's own distinctive key names
	// (ALL_VERSION=/"total count ="), not anything read out of the still
	// AES-encrypted host_info.dat, is what the attribution rests on -- see
	// vendor.NeusoftPlatformLabel.
	if versionsOK && rootfsOK {
		fmt.Printf("%sPlatform:     %s\n", indent, vendor.NeusoftPlatformLabel)
	}
	return printed
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
