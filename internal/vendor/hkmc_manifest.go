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
				out = append(out, FileClaim{Path: dir + vpath.Join(e.Dir, e.Name), Size: e.Size, Algo: algoCRC32, Sum: fmt.Sprintf("%08x", e.CRC)})
			}
		}
	}
	return out
}

// VerEntry is one file a .ver manifest lists.
type VerEntry struct {
	Dir  string // the sub-directory column 0 names after the collection, as a slash path; "" for none
	Name string
	CRC  uint32
	Size int64
}

// VerManifest is the parsed .ver of a downloaded firmware collection: the
// downloader writes one beside the parts, as pipe-separated rows
//
//	<collection>|<file>|<id>|<signed crc32>|<size>|<flag>
//
// after a header row "+|<id>|<build>|<brand>|<collection>|<n>|<flag>". Column 0 is
// the collection and, for a file kept in a sub-directory of it, that directory,
// backslash-separated (2019_21_G70_CAN\DAUDIOPLUS\can\ik\update).
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
			m.Collection, _, _ = strings.Cut(f[0], `\`)
		}
		m.Entries = append(m.Entries, VerEntry{Dir: verDir(f[0], m.Collection), Name: f[1], CRC: uint32(crc), Size: size})
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

// verDir is the sub-directory column 0 of a .ver row names after its collection,
// as a slash path: "COLL\DAUDIOPLUS\can" is "DAUDIOPLUS/can". The collection is
// what the header row gave, else what precedes the first backslash.
func verDir(col, collection string) string {
	rest, ok := strings.CutPrefix(col, collection+`\`)
	if !ok || collection == "" {
		_, rest, ok = strings.Cut(col, `\`)
	}
	if !ok {
		return ""
	}
	return strings.Trim(strings.ReplaceAll(rest, `\`, "/"), "/")
}
