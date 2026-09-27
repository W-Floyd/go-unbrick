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
	"strconv"
	"strings"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
)

type Library struct {
	Root string
	// BuildNamer names a stock build from its contents, letting the vendor layer
	// supply the OEM's own build stamp (see vendor.StockBuildID). Optional: when
	// nil or when it yields "", builds fall back to a content-hash name.
	BuildNamer func(vendor string, t *blankflash.Target) string
}

func Open(root string) *Library { return &Library{Root: root} }

// nameBuild resolves a build id: the caller's explicit choice, else the vendor's
// stamp, else a content hash.
func (l *Library) nameBuild(vendor, build string, t *blankflash.Target, sha string) string {
	if build == "" && l.BuildNamer != nil {
		build = l.BuildNamer(vendor, t)
	}
	if build == "" {
		build = "stock-" + sha[:12]
	}
	return build
}

// MigrateStock normalizes every device still stored in the pre-build-keyed flat
// layout. It is idempotent and a no-op once the library is converted; callers
// run it before listing or resolving stock so no device silently disappears
// from the catalogue just because it has not been re-imported yet.
func (l *Library) MigrateStock() error {
	base := filepath.Join(l.Root, "stock")
	vendors, _ := os.ReadDir(base)
	for _, v := range vendors {
		if !v.IsDir() {
			continue
		}
		devs, _ := os.ReadDir(filepath.Join(base, v.Name()))
		for _, d := range devs {
			if !d.IsDir() {
				continue
			}
			if err := l.migrateFlatStock(v.Name(), d.Name()); err != nil {
				return fmt.Errorf("migrating %s/%s: %w", v.Name(), d.Name(), err)
			}
		}
	}
	return nil
}

func familyDir(f catalog.Family) string { return filepath.Join(f.Vendor, f.JTAGID) }

// familyLoaderDir holds one subdirectory per distinct loader build in a family.
func (l *Library) familyLoaderDir(f catalog.Family) string {
	return filepath.Join(l.Root, "loaders", familyDir(f))
}
func (l *Library) buildDir(f catalog.Family, build string) string {
	return filepath.Join(l.familyLoaderDir(f), build)
}

// stockDeviceDir holds one subdirectory per distinct stock build of a device,
// mirroring how loaders are kept per build within a family.
func (l *Library) stockDeviceDir(vendor, codename string) string {
	return filepath.Join(l.Root, "stock", vendor, codename)
}
func (l *Library) StockBuildDir(vendor, codename, build string) string {
	return l.stockBuildDir(vendor, codename, build)
}

func (l *Library) stockBuildDir(vendor, codename, build string) string {
	return filepath.Join(l.stockDeviceDir(vendor, codename), build)
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
	// Peek is the loader's peek/poke memory-command support, as
	// secboot.PeekSupport.String() spells it ("enabled", "gated…", "none",
	// "n/a…", "unknown…"). Empty in meta written before this field existed;
	// reindex backfills it.
	Peek string `json:"peek,omitempty"`
}

type StockMeta struct {
	Storage string `json:"storage,omitempty"`
	// FlashOrder is the order the device's own recipe flashes its partitions
	// in. Without it a forged package falls back to a fixed list and silently
	// omits whatever that list lacks.
	FlashOrder []string          `json:"flash_order,omitempty"`
	FlashMap   map[string]string `json:"flash_map"`
	// CID and SubsidyLock are the channel identity the package's flashfile.xml
	// declares: the CID a device must report for the bootloader to accept this
	// build, and the subsidy-lock config that names that channel. Harvesting them
	// per build is what lets a CID be resolved to a channel from evidence instead
	// of a guessed table.
	CID         string `json:"cid,omitempty"`
	SubsidyLock string `json:"subsidy_lock,omitempty"`
	Source      string `json:"source"`
	Added       string `json:"added"`
	SHA256      string `json:"sha256"` // over parts+GPT, to dedupe re-imports
}

// stockSum hashes a target's parts and GPT so the same extract, imported twice
// under different filenames, is recognized as one build.
func stockSum(t *blankflash.Target) string {
	h := sha256.New()
	for _, fn := range sortedKeys(t.Parts) {
		fmt.Fprintf(h, "%s:%d\n", fn, len(t.Parts[fn]))
		h.Write(t.Parts[fn])
	}
	h.Write(t.GPT)
	return hex.EncodeToString(h.Sum(nil))
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
			// Backfill the donor's recipe onto loaders stored before it was
			// kept, so an existing library gains it without re-importing.
			if err := writeRecipes(l.buildDir(f, ref.Build), d.Recipes); err != nil {
				return nil, err
			}
			return &ref, nil
		}
	}
	build := buildID(source, sha)
	dir := l.buildDir(f, build)
	if err := writeFile(filepath.Join(dir, "programmer.elf"), d.Programmer); err != nil {
		return nil, err
	}
	if err := writeRecipes(dir, d.Recipes); err != nil {
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
	if id, err := secboot.FromImage(d.Programmer); err == nil {
		meta.OEMID, meta.HWID, meta.JTAGID, meta.SWID, meta.Root = id.OEMID, id.HWID, id.JTAGID, id.SWID, id.Root
	}
	meta.Peek = secboot.ScanPeek(d.Programmer).String()
	if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		return nil, err
	}
	return &LoaderRef{Family: f, Build: build, Meta: meta}, nil
}

// writeRecipes keeps the donor's own qboot recipe alongside its loader. The
// recipe carries the backup/restore directives that preserve per-device
// partitions across a flash, which a forged package must reproduce; without it
// stored here, a loader taken from the library cannot supply them.
func writeRecipes(dir string, recipes map[string][]byte) error {
	for n, b := range recipes {
		if err := writeFile(filepath.Join(dir, "recipe", filepath.Base(n)), b); err != nil {
			return err
		}
	}
	return nil
}

// readRecipes restores what writeRecipes kept.
func readRecipes(dir string) map[string][]byte {
	entries, err := os.ReadDir(filepath.Join(dir, "recipe"))
	if err != nil {
		return nil
	}
	out := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(dir, "recipe", e.Name())); err == nil {
			out[e.Name()] = b
		}
	}
	return out
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

// ReindexChange is one stored loader whose secboot fields re-derive differently.
type ReindexChange struct {
	Ref          LoaderRef
	OldSWID      uint64
	NewSWID      uint64
	FieldChanged []string
	// MovedTo is the family the loader belongs in when it was filed under
	// another; Duplicate means that family already holds the same programmer.
	MovedTo   *catalog.Family
	Duplicate bool
}

// Reindex re-derives every stored loader's secboot fields from its
// programmer.elf, for a library filed before the derivation changed (MBN v6
// metadata SW_IDs replaced the leaf cert's), and moves loaders whose family
// JTAG no longer matches — chiefly those filed under their own harvest hash
// prefix, which the old filename fallback mistook for a HW_ID. Donor-zip
// loaders are left where they are: their family comes from the catalog. With
// write false it only reports.
func (l *Library) Reindex(write bool) ([]ReindexChange, error) {
	var out []ReindexChange
	shas := map[string]map[string]bool{} // family → programmer shas it holds
	for _, f := range l.Loaders() {
		set := map[string]bool{}
		for _, ref := range l.Builds(f) {
			set[ref.Meta.SHA256] = true
		}
		shas[f.String()] = set
	}
	for _, f := range l.Loaders() {
		for _, ref := range l.Builds(f) {
			data, err := os.ReadFile(l.LoaderPath(ref))
			if err != nil {
				continue
			}
			m := ref.Meta
			var changed []string
			// Peek is backfilled for every loader, signed or not — the
			// streaming loaders that FromImage rejects are exactly the PeekNA
			// ones, so it is computed before the signature guard.
			if peek := secboot.ScanPeek(data).String(); peek != m.Peek {
				m.Peek = peek
				changed = append(changed, "peek")
			}
			id, err := secboot.FromImage(data)
			if err != nil {
				if len(changed) == 0 {
					continue
				}
				out = append(out, ReindexChange{Ref: ref, OldSWID: m.SWID, NewSWID: m.SWID, FieldChanged: changed})
				if write {
					if werr := writeJSON(filepath.Join(l.buildDir(f, ref.Build), "meta.json"), m); werr != nil {
						return out, werr
					}
				}
				continue
			}
			for _, c := range []struct {
				name     string
				old, new string
			}{
				{"oem_id", m.OEMID, id.OEMID}, {"hw_id", m.HWID, id.HWID},
				{"jtag_id", m.JTAGID, id.JTAGID}, {"root", m.Root, id.Root},
				{"sw_id", fmt.Sprint(m.SWID), fmt.Sprint(id.SWID)},
			} {
				if c.old != c.new {
					changed = append(changed, c.name)
				}
			}
			var move *catalog.Family
			if !strings.HasSuffix(strings.ToLower(m.Source), ".zip") {
				orig, _ := OriginalName(m.Source, data)
				if want := FamilyJTAG(id.JTAGID, orig); want != f.JTAGID {
					move = &catalog.Family{Vendor: f.Vendor, JTAGID: want}
				}
			}
			if len(changed) == 0 && move == nil {
				continue
			}
			ch := ReindexChange{Ref: ref, OldSWID: m.SWID, NewSWID: id.SWID, FieldChanged: changed, MovedTo: move}
			if move != nil {
				dest := shas[move.String()]
				if dest == nil {
					dest = map[string]bool{}
					shas[move.String()] = dest
				}
				ch.Duplicate = dest[m.SHA256]
				dest[m.SHA256] = true
			}
			out = append(out, ch)
			if !write {
				continue
			}
			m.OEMID, m.HWID, m.JTAGID, m.SWID, m.Root = id.OEMID, id.HWID, id.JTAGID, id.SWID, id.Root
			dir := l.buildDir(f, ref.Build)
			if err := writeJSON(filepath.Join(dir, "meta.json"), m); err != nil {
				return out, err
			}
			if move == nil {
				continue
			}
			if ch.Duplicate {
				if err := os.RemoveAll(dir); err != nil {
					return out, err
				}
				continue
			}
			dst := l.buildDir(*move, ref.Build)
			if _, err := os.Stat(dst); err == nil {
				dst += "_" + m.SHA256[:8] // same build name, different programmer
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return out, err
			}
			if err := os.Rename(dir, dst); err != nil {
				return out, err
			}
		}
		// A family emptied by the moves goes too.
		if write {
			if left, err := os.ReadDir(l.familyLoaderDir(f)); err == nil && len(left) == 0 {
				_ = os.Remove(l.familyLoaderDir(f))
			}
		}
	}
	return out, nil
}

// LoaderPath is where a stored build's programmer lives on disk.
func (l *Library) LoaderPath(ref LoaderRef) string {
	return filepath.Join(l.buildDir(ref.Family, ref.Build), "programmer.elf")
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
		Recipes:    readRecipes(dir),
		CPUName:    ref.Meta.CPUName,
		Storage:    ref.Meta.Storage,
		Source:     "library:" + f.String() + "@" + ref.Build,
	}
	return d, ref, nil
}

// AddStock stores one build of a device's harvested boot partitions + GPT,
// alongside any builds already kept for that device. build names it (from the
// OEM's own stamp, via the vendor driver); when empty, a content hash is used.
// Re-importing the same bytes is a no-op returning the existing build.
func (l *Library) AddStock(vendor, codename, build string, t *blankflash.Target) (*StockRef, error) {
	if err := l.migrateFlatStock(vendor, codename); err != nil {
		return nil, err
	}
	sha := stockSum(t)
	for _, ref := range l.StockBuilds(vendor, codename) {
		if ref.Meta.SHA256 == sha {
			// Same bytes, but the metadata may predate a field. Refresh it so an
			// existing library gains the flash order without re-importing.
			stale := false
			if len(ref.Meta.FlashOrder) == 0 && len(t.FlashOrder) > 0 {
				ref.Meta.FlashOrder = t.FlashOrder
				stale = true
			}
			if ref.Meta.CID == "" && t.CID != "" {
				ref.Meta.CID, ref.Meta.SubsidyLock = t.CID, t.SubsidyLock
				stale = true
			}
			if stale {
				dir := l.stockBuildDir(vendor, codename, ref.Build)
				if err := writeJSON(filepath.Join(dir, "meta.json"), ref.Meta); err != nil {
					return nil, err
				}
			}
			return &ref, nil
		}
	}
	build = l.nameBuild(vendor, build, t, sha)
	dir := l.stockBuildDir(vendor, codename, build)
	if err := os.RemoveAll(dir); err != nil { // replace wholesale to avoid stale parts
		return nil, err
	}
	meta := StockMeta{
		Storage:     t.Storage,
		FlashOrder:  t.FlashOrder,
		FlashMap:    t.FlashMap,
		CID:         t.CID,
		SubsidyLock: t.SubsidyLock,
		Source:      t.Source,
		Added:       time.Now().UTC().Format(time.RFC3339),
		SHA256:      sha,
	}
	if err := l.writeStock(dir, t, meta); err != nil {
		return nil, err
	}
	return &StockRef{Vendor: vendor, Codename: codename, Build: build, Meta: meta}, nil
}

func (l *Library) writeStock(dir string, t *blankflash.Target, meta StockMeta) error {
	for fn, b := range t.Parts {
		if err := writeFile(filepath.Join(dir, "parts", fn), b); err != nil {
			return err
		}
	}
	if t.GPT != nil {
		if err := writeFile(filepath.Join(dir, "gpt.bin"), t.GPT); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(dir, "meta.json"), meta)
}

// migrateFlatStock moves a pre-build-keyed layout (parts/ and meta.json directly
// under the device dir) into a build subdirectory, so earlier imports survive
// rather than being orphaned by the new layout.
func (l *Library) migrateFlatStock(vendor, codename string) error {
	dev := l.stockDeviceDir(vendor, codename)
	if _, err := os.Stat(filepath.Join(dev, "meta.json")); err != nil {
		return nil // already build-keyed, or nothing stored
	}
	t, meta, err := l.readStock(dev)
	if err != nil {
		return err
	}
	if meta.SHA256 == "" {
		meta.SHA256 = stockSum(t)
	}
	build := l.nameBuild(vendor, "", t, meta.SHA256)
	tmp := dev + ".migrating"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := l.writeStock(tmp, t, meta); err != nil {
		return err
	}
	// Only discard the old layout once the copy is safely written.
	for _, n := range []string{"parts", "gpt.bin", "meta.json"} {
		if err := os.RemoveAll(filepath.Join(dev, n)); err != nil {
			return err
		}
	}
	return os.Rename(tmp, l.stockBuildDir(vendor, codename, build))
}

func (l *Library) HasStock(vendor, codename string) bool {
	return len(l.StockBuilds(vendor, codename)) > 0
}

// StockBuilds lists a device's stored stock builds, newest (by build id, which
// the vendor stamps date-first) last.
func (l *Library) StockBuilds(vendor, codename string) []StockRef {
	entries, err := os.ReadDir(l.stockDeviceDir(vendor, codename))
	if err != nil {
		return nil
	}
	var out []StockRef
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var meta StockMeta
		b, err := os.ReadFile(filepath.Join(l.stockBuildDir(vendor, codename, e.Name()), "meta.json"))
		if err != nil {
			continue
		}
		_ = json.Unmarshal(b, &meta)
		out = append(out, StockRef{Vendor: vendor, Codename: codename, Build: e.Name(), Meta: meta})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Build < out[j].Build })
	return out
}

// readStock loads a Target and its metadata from one stored stock directory.
func (l *Library) readStock(dir string) (*blankflash.Target, StockMeta, error) {
	var meta StockMeta
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, meta, err
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, meta, err
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
		Parts:       parts,
		FlashMap:    meta.FlashMap,
		FlashOrder:  meta.FlashOrder,
		GPT:         gpt,
		Storage:     meta.Storage,
		CID:         meta.CID,
		SubsidyLock: meta.SubsidyLock,
	}, meta, nil
}

// FindStock rebuilds a Target from stored stock for a device. build selects a
// specific stored build; empty takes the newest.
func (l *Library) FindStock(vendor, codename, build string) (*blankflash.Target, *StockRef, error) {
	builds := l.StockBuilds(vendor, codename)
	if len(builds) == 0 {
		return nil, nil, fmt.Errorf("no stock for %s/%s", vendor, codename)
	}
	ref := &builds[len(builds)-1] // newest: build ids sort chronologically
	if build != "" {
		ref = nil
		for i := range builds {
			if builds[i].Build == build {
				ref = &builds[i]
				break
			}
		}
		if ref == nil {
			return nil, nil, fmt.Errorf("no stock build %q for %s/%s", build, vendor, codename)
		}
	}
	t, _, err := l.readStock(l.stockBuildDir(vendor, codename, ref.Build))
	if err != nil {
		return nil, nil, err
	}
	t.Source = "library:" + vendor + "/" + codename + "@" + ref.Build
	return t, ref, nil
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

// LoadersForJTAGs returns every stored loader under the given JTAG_ID families
// for a vendor, lowest-SW_ID first. This is the authoritative device↔loader
// resolution: a loader in a device's JTAG family authenticates by the fused
// HW_ID the PBL checks, independent of the lossy cpu_name label. Preferred over
// LoadersForCPU whenever the device's JTAG_ID is known.
func (l *Library) LoadersForJTAGs(vendor string, jtags []string) []LoaderRef {
	var out []LoaderRef
	for _, j := range jtags {
		out = append(out, l.Builds(catalog.Family{Vendor: vendor, JTAGID: strings.ToUpper(j)})...)
	}
	sort.Slice(out, func(i, k int) bool {
		if out[i].Meta.SWID != out[k].Meta.SWID {
			return out[i].Meta.SWID < out[k].Meta.SWID
		}
		return out[i].Build < out[k].Build
	})
	return out
}

// CandidateLoaders resolves a device to its candidate loaders, lowest-SW_ID
// first: by the authoritative JTAG_ID key when the device records one, else via
// the cpu_name bridge. The single point where derive and `catalog list` agree.
//
// A pinned JTAG_ID does not rule out the cpu_name bridge entirely. A loader
// whose cert we cannot parse is filed under its cpu_name instead of a JTAG, so
// its silicon is unknown rather than known-different; excluding it would leave a
// device with a recorded JTAG_ID no loader at all. So the bridge still answers
// when the JTAG key finds nothing.
func (l *Library) CandidateLoaders(d *catalog.Device) []LoaderRef {
	if len(d.JTAGIDs) > 0 {
		if out := l.LoadersForJTAGs(d.Vendor, d.JTAGIDs); len(out) > 0 {
			return out
		}
	}
	return l.LoadersForCPU(d.Vendor, d.CPUName)
}

// HasLoaderForCPU reports whether any stored loader serves a device's cpu_name.
func (l *Library) HasLoaderForCPU(vendor, cpu string) bool {
	return len(l.LoadersForCPU(vendor, cpu)) > 0
}

// NormalizeCID renders a Motorola CID in the canonical hex spelling flashfile.xml
// and `fastboot getvar cid` share, so a device's report and a package's claim
// compare as strings. Unparseable input is returned trimmed, never dropped.
func NormalizeCID(cid string) string {
	v := strings.TrimSpace(cid)
	base := 10
	if lower := strings.ToLower(v); strings.HasPrefix(lower, "0x") {
		v, base = lower[2:], 16
	}
	n, err := strconv.ParseUint(v, base, 64)
	if err != nil {
		return strings.TrimSpace(cid)
	}
	return fmt.Sprintf("0x%04X", n)
}

// CarrierIDs reports the CID -> subsidy-lock-config pairs every stored stock build
// declared, keyed by NormalizeCID. It is the evidence behind catalog/carrier_ids.yaml:
// a CID the catalog does not name can still be identified from a package that
// targeted it, and new pairs accrue as builds land rather than being hand-entered.
func (l *Library) CarrierIDs() map[string]string {
	out := map[string]string{}
	for _, s := range l.Stock() {
		if s.Meta.CID == "" {
			continue
		}
		if cid := NormalizeCID(s.Meta.CID); out[cid] == "" {
			out[cid] = s.Meta.SubsidyLock
		}
	}
	return out
}

// StockRef is a vendor/codename pair with stored stock.
type StockRef struct {
	Vendor, Codename string
	Build            string
	Meta             StockMeta
}

// Stock lists every stored stock build, across all devices.
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
				out = append(out, l.StockBuilds(v.Name(), d.Name())...)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		if out[i].Codename != out[j].Codename {
			return out[i].Codename < out[j].Codename
		}
		return out[i].Build < out[j].Build
	})
	return out
}
