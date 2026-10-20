package vendor

import (
	"fmt"
	"io"
	vpath "path"
	"strconv"
	"strings"
)

const (
	algoHyundaiSHA224 = "hyundai-sha224"
	algoCRC32         = "crc32"
)

// Manifests implements ManifestReader: update.info and NEW_TarList's per-file
// HyundaiSHA224 hashes, and the downloader's .ver manifests (size and CRC32).
func (hkmc) Manifests(pkg PackageAccess) []FileClaim {
	var out []FileClaim
	for name := range pkg.Names {
		base := name[strings.LastIndex(name, "/")+1:]
		switch {
		case name == "update.info":
			for _, e := range ParseUpdateInfoEntries(pkg.Read(name)) {
				out = append(out, FileClaim{Path: vpath.Join(e.Dir, e.Name), Size: -1, Algo: algoHyundaiSHA224, Sum: e.Hash})
			}
		case strings.HasSuffix(base, "TarList.txt_encrypted"):
			dir := name[:len(name)-len(base)]
			for _, line := range strings.Split(string(DecodeTarList(pkg.Read(name))), "\n") {
				rest, ok := strings.CutPrefix(strings.TrimSpace(line), "@FILE:")
				if !ok {
					continue
				}
				if f := strings.Split(rest, ","); len(f) >= 3 {
					out = append(out, FileClaim{Path: dir + f[0], Size: -1, Algo: algoHyundaiSHA224, Sum: f[2]})
				}
			}
		case strings.HasSuffix(strings.ToLower(base), ".ver"):
			dir := name[:len(name)-len(base)]
			for _, e := range ParseVer(pkg.Read(name)).Entries {
				out = append(out, FileClaim{Path: dir + e.Name, Size: e.Size, Algo: algoCRC32, Sum: fmt.Sprintf("%08x", e.CRC)})
			}
		}
	}
	return out
}

// VerEntry is one file a .ver manifest lists.
type VerEntry struct {
	Name string
	CRC  uint32
	Size int64
}

// VerManifest is the parsed .ver of a downloaded firmware collection: the
// downloader writes one beside the parts, as pipe-separated rows
//
//	<collection>|<file>|<id>|<signed crc32>|<size>|<flag>
//
// after a header row "+|<id>|<build>|<brand>|<collection>|<n>|<flag>".
type VerManifest struct {
	Collection string // target device, e.g. 2022_EV6_USA
	Build      string
	Entries    []VerEntry
}

// ParseVer reads a .ver; Entries is empty when data is not one.
func ParseVer(data []byte) VerManifest {
	var m VerManifest
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) < 5 {
			continue
		}
		if f[0] == "+" {
			m.Build = f[2]
			m.Collection = f[4]
			continue
		}
		crc, err1 := strconv.ParseInt(f[3], 10, 64)
		size, err2 := strconv.ParseInt(f[4], 10, 64)
		if err1 != nil || err2 != nil || f[1] == "" {
			continue
		}
		if m.Collection == "" {
			m.Collection = f[0]
		}
		m.Entries = append(m.Entries, VerEntry{Name: f[1], CRC: uint32(crc), Size: size})
	}
	return m
}

// Hasher implements Hasher for the digest its manifests use.
func (hkmc) Hasher(algo string) func(io.Reader) (string, error) {
	if algo == algoHyundaiSHA224 {
		return HyundaiSHA224
	}
	return nil
}
