// Package library is the on-disk store of the reusable, binary pieces: signed
// loaders (indexed by family) and harvested stock firmware (indexed by device).
// It is gitignored — firmware never enters the repo. The catalog references it;
// this package rebuilds blankflash.Donor / blankflash.Target from what it holds.
package library

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go-unbrick/internal/blankflash"
	"go-unbrick/internal/catalog"
	"go-unbrick/internal/secboot"
)

type Library struct{ Root string }

func Open(root string) *Library { return &Library{Root: root} }

func familyDir(f catalog.Family) string { return filepath.Join(f.Vendor, f.JTAGID) }

// familyLoaderDir holds one subdirectory per distinct loader build in a family.
func (l *Library) familyLoaderDir(f catalog.Family) string {
	return filepath.Join(l.Root, "loaders", familyDir(f))
}
func (l *Library) buildDir(f catalog.Family, build string) string {
	return filepath.Join(l.familyLoaderDir(f), build)
}
func (l *Library) stockDir(vendor, codename string) string {
	return filepath.Join(l.Root, "stock", vendor, codename)
}

// buildID names a loader build from the donor it came from, e.g.
// "blankflash_rhode_T2SRS33.72-22-4-1_rebuild.zip" -> "rhode_T2SRS33.72-22-4-1".
// Falls back to a sha256 prefix when nothing usable remains.
func buildID(source, sha string) string {
	base := filepath.Base(source)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.TrimPrefix(base, "blankflash_")
	base = strings.TrimSuffix(base, "_rebuild")
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		default:
			return '-'
		}
	}, base)
	base = strings.Trim(base, "-")
	if base == "" {
		return "loader-" + sha[:12]
	}
	return base
}

type LoaderMeta struct {
	CPUName string `json:"cpu_name"`
	Storage string `json:"storage,omitempty"`
	Source  string `json:"source"` // donor codename or path the loader came from
	SHA256  string `json:"sha256"` // of programmer.elf, to dedupe/verify
	Added   string `json:"added"`
	// Secboot identity parsed from the loader's cert chain (best-effort).
	OEMID  string   `json:"oem_id,omitempty"`
	HWID   string   `json:"hw_id,omitempty"`
	JTAGID string   `json:"jtag_id,omitempty"`
	SWID   uint64   `json:"sw_id"` // anti-rollback counter; derive prefers the lowest
	Root   string   `json:"root,omitempty"`
	Qboot  []string `json:"qboot,omitempty"`
}

type StockMeta struct {
	Storage  string            `json:"storage,omitempty"`
	FlashMap map[string]string `json:"flash_map"`
	Source   string            `json:"source"`
	Added    string            `json:"added"`
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, b)
}

// LoaderRef identifies one stored loader build within a family.
type LoaderRef struct {
	Family catalog.Family
	Build  string
	Meta   LoaderMeta
}

// AddLoader stores a loader build (one per distinct source) under its family.
// If a build with the same programmer.elf SHA256 is already present, it is not
// duplicated and the existing ref is returned. source names the donor it came
// from, for provenance and to derive the build id.
func (l *Library) AddLoader(f catalog.Family, d *blankflash.Donor, source string) (*LoaderRef, error) {
	sum := sha256.Sum256(d.Programmer)
	sha := hex.EncodeToString(sum[:])
	for _, ref := range l.Builds(f) { // dedupe identical loaders across build ids
		if ref.Meta.SHA256 == sha {
			return &ref, nil
		}
	}
	build := buildID(source, sha)
	dir := l.buildDir(f, build)
	if err := writeFile(filepath.Join(dir, "programmer.elf"), d.Programmer); err != nil {
		return nil, err
	}
	qbootNames := make([]string, 0, len(d.Qboot))
	for n, b := range d.Qboot {
		if err := writeFile(filepath.Join(dir, "aux", n), b); err != nil {
			return nil, err
		}
		qbootNames = append(qbootNames, n)
	}
	sort.Strings(qbootNames)
	meta := LoaderMeta{
		CPUName: d.CPUName, // qboot label from the donor index.xml; blank for a bare fhprg
		Storage: d.Storage,
		Source:  source,
		SHA256:  sha,
		Added:   time.Now().UTC().Format(time.RFC3339),
		Qboot:   qbootNames,
	}
	if id, err := secboot.FromELF(d.Programmer); err == nil {
		meta.OEMID, meta.HWID, meta.JTAGID, meta.SWID, meta.Root = id.OEMID, id.HWID, id.JTAGID, id.SWID, id.Root
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		return nil, err
	}
	return &LoaderRef{Family: f, Build: build, Meta: meta}, nil
}

func (l *Library) HasLoader(f catalog.Family) bool { return len(l.Builds(f)) > 0 }

// Builds lists a family's stored loader builds, newest (by Added) first.
func (l *Library) Builds(f catalog.Family) []LoaderRef {
	entries, err := os.ReadDir(l.familyLoaderDir(f))
	if err != nil {
		return nil
	}
	var out []LoaderRef
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var meta LoaderMeta
		if b, err := os.ReadFile(filepath.Join(l.buildDir(f, e.Name()), "meta.json")); err == nil {
			_ = json.Unmarshal(b, &meta)
		}
		out = append(out, LoaderRef{Family: f, Build: e.Name(), Meta: meta})
	}
	// Lowest SW_ID first: a rejected loader is harmless (stalls at Sahara), an
	// over-high one may permanently advance the target's anti-rollback fuse. So
	// derive defaults to the lowest and the user escalates only on rejection.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Meta.SWID != out[j].Meta.SWID {
			return out[i].Meta.SWID < out[j].Meta.SWID
		}
		return out[i].Build < out[j].Build
	})
	return out
}

// FindLoader rebuilds a Donor from a family's loader. build selects a specific
// build id; empty picks the lowest SW_ID (safest against anti-rollback lock-out).
func (l *Library) FindLoader(f catalog.Family, build string) (*blankflash.Donor, *LoaderRef, error) {
	builds := l.Builds(f)
	if len(builds) == 0 {
		return nil, nil, fmt.Errorf("no loader for family %s", f)
	}
	var ref *LoaderRef
	if build == "" {
		ref = &builds[0]
	} else {
		for i := range builds {
			if builds[i].Build == build {
				ref = &builds[i]
				break
			}
		}
		if ref == nil {
			return nil, nil, fmt.Errorf("no loader build %q for family %s", build, f)
		}
	}
	dir := l.buildDir(f, ref.Build)
	prog, err := os.ReadFile(filepath.Join(dir, "programmer.elf"))
	if err != nil {
		return nil, nil, err
	}
	qboot := map[string][]byte{}
	if entries, err := os.ReadDir(filepath.Join(dir, "aux")); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(dir, "aux", e.Name())); err == nil {
				qboot[e.Name()] = b
			}
		}
	}
	d := &blankflash.Donor{
		Programmer: prog,
		Qboot:      qboot,
		CPUName:    ref.Meta.CPUName,
		Storage:    ref.Meta.Storage,
		Source:     "library:" + f.String() + "@" + ref.Build,
	}
	return d, ref, nil
}

// AddStock stores a device's harvested boot partitions + GPT.
func (l *Library) AddStock(vendor, codename string, t *blankflash.Target) (string, error) {
	dir := l.stockDir(vendor, codename)
	if err := os.RemoveAll(dir); err != nil { // replace wholesale to avoid stale parts
		return "", err
	}
	for fn, b := range t.Parts {
		if err := writeFile(filepath.Join(dir, "parts", fn), b); err != nil {
			return "", err
		}
	}
	if t.GPT != nil {
		if err := writeFile(filepath.Join(dir, "gpt.bin"), t.GPT); err != nil {
			return "", err
		}
	}
	meta := StockMeta{
		Storage:  t.Storage,
		FlashMap: t.FlashMap,
		Source:   t.Source,
		Added:    time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		return "", err
	}
	return dir, nil
}

func (l *Library) HasStock(vendor, codename string) bool {
	_, err := os.Stat(filepath.Join(l.stockDir(vendor, codename), "meta.json"))
	return err == nil
}

// FindStock rebuilds a Target from stored stock for a device.
func (l *Library) FindStock(vendor, codename string) (*blankflash.Target, error) {
	dir := l.stockDir(vendor, codename)
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, fmt.Errorf("no stock for %s/%s: %w", vendor, codename, err)
	}
	var meta StockMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, err
	}
	parts := map[string][]byte{}
	if entries, err := os.ReadDir(filepath.Join(dir, "parts")); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if pb, err := os.ReadFile(filepath.Join(dir, "parts", e.Name())); err == nil {
				parts[e.Name()] = pb
			}
		}
	}
	var gpt []byte
	if gb, err := os.ReadFile(filepath.Join(dir, "gpt.bin")); err == nil {
		gpt = gb
	}
	return &blankflash.Target{
		Parts:    parts,
		FlashMap: meta.FlashMap,
		GPT:      gpt,
		Storage:  meta.Storage,
		Source:   "library:" + vendor + "/" + codename,
	}, nil
}

// Loaders lists the families with a stored loader.
func (l *Library) Loaders() []catalog.Family {
	var out []catalog.Family
	base := filepath.Join(l.Root, "loaders")
	vendors, _ := os.ReadDir(base)
	for _, v := range vendors {
		if !v.IsDir() {
			continue
		}
		jtags, _ := os.ReadDir(filepath.Join(base, v.Name()))
		for _, j := range jtags {
			if !j.IsDir() {
				continue
			}
			f := catalog.Family{Vendor: v.Name(), JTAGID: j.Name()}
			if len(l.Builds(f)) > 0 {
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// LoadersForCPU bridges a device's cpu_name to the JTAG-keyed loader store: it
// returns every stored loader whose recorded cpu_name matches (case-insensitive),
// across all JTAG families, ordered lowest-SW_ID first (safest against anti-
// rollback lock-out). This is the emergent device↔loader link — a full donor that
// carries both cpu_name (index.xml) and JTAG_ID (cert) pulls in bare fhprg loaders
// sharing that JTAG, even though those carry no cpu_name of their own.
func (l *Library) LoadersForCPU(vendor, cpu string) []LoaderRef {
	if cpu == "" {
		return nil
	}
	want := strings.ToLower(cpu)
	jtags := map[string]bool{} // JTAGs seen under this cpu_name
	var out []LoaderRef
	for _, f := range l.Loaders() {
		if f.Vendor != vendor {
			continue
		}
		for _, ref := range l.Builds(f) {
			if strings.EqualFold(ref.Meta.CPUName, cpu) {
				jtags[f.JTAGID] = true
			}
		}
	}
	for _, f := range l.Loaders() {
		if f.Vendor != vendor || !jtags[f.JTAGID] {
			continue
		}
		for _, ref := range l.Builds(f) {
			// A bare fhprg under a matched JTAG has no cpu_name but is still
			// compatible; a cpu_name that mismatches the label is excluded.
			if ref.Meta.CPUName == "" || strings.ToLower(ref.Meta.CPUName) == want {
				out = append(out, ref)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Meta.SWID != out[j].Meta.SWID {
			return out[i].Meta.SWID < out[j].Meta.SWID
		}
		return out[i].Build < out[j].Build
	})
	return out
}

// HasLoaderForCPU reports whether any stored loader serves a device's cpu_name.
func (l *Library) HasLoaderForCPU(vendor, cpu string) bool {
	return len(l.LoadersForCPU(vendor, cpu)) > 0
}

// StockRef is a vendor/codename pair with stored stock.
type StockRef struct{ Vendor, Codename string }

// Stock lists the devices with stored stock firmware.
func (l *Library) Stock() []StockRef {
	var out []StockRef
	base := filepath.Join(l.Root, "stock")
	vendors, _ := os.ReadDir(base)
	for _, v := range vendors {
		if !v.IsDir() {
			continue
		}
		devs, _ := os.ReadDir(filepath.Join(base, v.Name()))
		for _, d := range devs {
			if d.IsDir() {
				out = append(out, StockRef{Vendor: v.Name(), Codename: d.Name()})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		return out[i].Codename < out[j].Codename
	})
	return out
}
