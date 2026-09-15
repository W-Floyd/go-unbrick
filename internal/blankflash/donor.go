package blankflash

// Ingest a donor blankflash and lift the reusable, signed pieces out of it.
//
// A blankflash is a directory (or zip) holding singleimage.bin plus the qboot
// flasher. The signed programmer.elf (the Firehose loader) lives inside the
// singleimage and is authenticated by the SoC's secure-boot chain against the OEM
// key -- so it is reusable across every device that shares that SoC + OEM key,
// which is the whole premise of this tool.

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var qbootNames = []string{"qboot", "qboot.exe", "qboot.dll", "blank-flash.bat", "blank-flash.sh"}

type Donor struct {
	Programmer []byte            // the signed Firehose loader
	Recipes    map[string][]byte // index.xml / pkg.xml / default.xml (donor's own)
	Qboot      map[string][]byte // flasher binaries, by name
	CPUName    string            // qboot cpu.name from index.xml
	Storage    string            // storage.type from index.xml (UFS / eMMC)
	Source     string
}

// readDirOrZip flattens a blankflash directory or zip into {basename: bytes}.
func readDirOrZip(path string) (map[string][]byte, error) {
	files := map[string][]byte{}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				files[filepath.Base(p)] = b
			}
			return nil
		})
		return files, err
	}
	if zr, err := zip.OpenReader(path); err == nil {
		defer zr.Close()
		for _, f := range zr.File {
			if strings.HasSuffix(f.Name, "/") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
			files[filepath.Base(f.Name)] = b
		}
		return files, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, ".bin") || IsContainer(b) {
		files[filepath.Base(path)] = b
		return files, nil
	}
	return nil, fmt.Errorf("donor is not a dir, zip, or singleimage: %s", path)
}

var (
	reCPU   = regexp.MustCompile(`cpu\.name:([^\s"]+)`)
	reStore = regexp.MustCompile(`storage\.type="([^"]+)"`)
)

func metaFromIndex(indexXML []byte) (cpu, storage string) {
	txt := string(indexXML)
	if m := reCPU.FindStringSubmatch(txt); m != nil {
		cpu = m[1]
	}
	if m := reStore.FindStringSubmatch(txt); m != nil {
		storage = m[1]
	}
	return
}

// containerHasLoader reports whether a container holds a loader/recipe (vs, say,
// a bare gpt.bin container of gpt_mainN.bin records).
func containerHasLoader(b []byte) bool {
	recs, err := Parse(b)
	if err != nil {
		return false
	}
	for _, r := range recs {
		if r.Name == "index.xml" || strings.HasPrefix(r.Name, "programmer.") {
			return true
		}
	}
	return false
}

func Ingest(path string) (*Donor, error) {
	files, err := readDirOrZip(path)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic selection independent of map order

	// Pick the singleimage container carefully: a UFS gpt.bin is itself a
	// SINGLE_N_LONELY container and sorts before singleimage.bin, so prefer the
	// exact name, then any container that actually holds a loader/recipe, and only
	// then fall back to the first container.
	var single []byte
	if b, ok := files["singleimage.bin"]; ok && IsContainer(b) {
		single = b
	}
	if single == nil {
		for _, name := range names {
			if b := files[name]; IsContainer(b) && strings.HasSuffix(name, ".bin") && containerHasLoader(b) {
				single = b
				break
			}
		}
	}
	if single == nil {
		for _, name := range names {
			if b := files[name]; IsContainer(b) && strings.HasSuffix(name, ".bin") {
				single = b
				break
			}
		}
	}
	if single == nil {
		for _, name := range names {
			if b := files[name]; IsContainer(b) {
				single = b
				break
			}
		}
	}
	if single == nil {
		return nil, fmt.Errorf("no SINGLE_N_LONELY singleimage found in donor")
	}
	recs, err := Parse(single)
	if err != nil {
		return nil, err
	}
	idx := Index(recs)

	// The Firehose loader is "programmer.elf" (newer) or "programmer.mbn" (older
	// eMMC/MSM packages, e.g. ginna). Fall back to any record named "programmer.*",
	// then to any .elf/.mbn carrying the Firehose <data> recipe signature.
	prog := idx["programmer.elf"]
	if prog == nil {
		prog = idx["programmer.mbn"]
	}
	if prog == nil {
		names := make([]string, 0, len(idx))
		for n := range idx {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			if strings.HasPrefix(name, "programmer.") {
				prog = idx[name]
				break
			}
		}
		if prog == nil {
			for _, name := range names {
				if strings.HasSuffix(name, ".elf") || strings.HasSuffix(name, ".mbn") {
					head := idx[name]
					if len(head) > 200000 {
						head = head[:200000]
					}
					if strings.Contains(string(head), "<data>") {
						prog = idx[name]
						break
					}
				}
			}
		}
	}
	if prog == nil {
		return nil, fmt.Errorf("donor singleimage has no programmer.elf/.mbn")
	}

	recipes := map[string][]byte{}
	for _, n := range []string{"index.xml", "pkg.xml", "default.xml"} {
		if v, ok := idx[n]; ok {
			recipes[n] = v
		}
	}
	cpu, storage := metaFromIndex(recipes["index.xml"])
	qboot := map[string][]byte{}
	for _, n := range qbootNames {
		if v, ok := files[n]; ok {
			qboot[n] = v
		}
	}

	return &Donor{
		Programmer: prog,
		Recipes:    recipes,
		Qboot:      qboot,
		CPUName:    cpu,
		Storage:    storage,
		Source:     path,
	}, nil
}
