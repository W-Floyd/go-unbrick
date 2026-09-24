package library

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v4"
)

// Knowledge is what recon has learned about one device model — the
// non-identifying facts (silicon, signing domain, carrier variant, stock
// firmware baseline). It is a local store under the library; nothing here
// fingerprints an individual unit (see facts.Learnable).
//
// Facts are kept as matching sets, not as independent per-fact lists: each
// Observation is the group of facts one recon saw *together*, so a carrier, its
// CID and its firmware are known to belong to the same variant rather than
// merely to have both been seen for the model. Only maximal sets are kept — an
// observation contained in a larger one is dropped — so the record stays the
// distinct configurations seen, with no counts and no churn between runs.
type Knowledge struct {
	Key       string `yaml:"key"`
	Vendor    string `yaml:"vendor,omitempty"`
	FirstSeen string `yaml:"first_seen"`
	// LastLearned is bumped only when an observation adds a new matching set,
	// so it dates the knowledge rather than the last time recon ran.
	LastLearned string `yaml:"last_learned"`
	// Observations are the distinct maximal matching sets seen. A single recon
	// sees only what its vantage exposes (adb: carrier+fingerprint; edl:
	// JTAG+CID+signing), and units are not tracked, so partial sets from
	// different vantages coexist rather than being stitched together.
	Observations []map[string]string `yaml:"observations"`
}

// Pin is a session buffer: the accumulating union of facts observed for one
// physical device the operator has explicitly declared the same across routes,
// by reusing a --pin label. It is what makes stitching sound — a partial set
// from adb and a partial set from edl are merged into one matching set only
// because the operator vouched they are the same unit, which recon never infers
// on its own (see Knowledge).
type Pin struct {
	Label  string            `yaml:"label"`
	Key    string            `yaml:"key,omitempty"`
	Vendor string            `yaml:"vendor,omitempty"`
	// IDs are the hashed hardware ids (serial, storage serial, chip serial) this
	// unit was seen under. A recon sharing any one of them is the same unit, so
	// auto-stitching unions buffers across routes that expose different ids —
	// fastboot's serial, ssh's storage serial — without any of them being stored.
	IDs   []string          `yaml:"ids,omitempty"`
	Facts map[string]string `yaml:"facts"`
}

// AddToPinAuto stitches by hardware identity: it merges every pin buffer that
// shares any of idHashes with this recon (and this recon's own facts) into one,
// so a unit seen over routes that expose different ids still resolves to a
// single session. Returns the merged pin. idHashes are hashes, never the raw
// serials.
func (l *Library) AddToPinAuto(vendor, key string, idHashes []string, add map[string]string) (*Pin, error) {
	if len(idHashes) == 0 {
		return nil, nil
	}
	dir := filepath.Join(l.knowledgeDir(), ".pins")
	want := map[string]bool{}
	for _, h := range idHashes {
		want[h] = true
	}
	merged := &Pin{Facts: map[string]string{}}
	var matched []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "auto_") || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		p := &Pin{}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || yaml.Unmarshal(b, p) != nil || !sharesID(p.IDs, want) {
			continue
		}
		matched = append(matched, filepath.Join(dir, e.Name()))
		for _, id := range p.IDs {
			want[id] = true
		}
		for k, v := range p.Facts {
			merged.Facts[k] = v
		}
		if merged.Key == "" {
			merged.Key, merged.Vendor = p.Key, p.Vendor
		}
	}
	for k, v := range add {
		merged.Facts[k] = v // this recon's facts win on overlap (freshest)
	}
	if key != "" {
		merged.Key, merged.Vendor = key, vendor
	}
	merged.IDs = sortedKeysOf(want)
	merged.Label = "auto_" + merged.IDs[0]
	target := filepath.Join(dir, merged.Label+".yaml")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return merged, err
	}
	out, err := yaml.Marshal(merged)
	if err != nil {
		return merged, err
	}
	if err := os.WriteFile(target, out, 0o644); err != nil {
		return merged, err
	}
	for _, f := range matched { // drop the buffers the union absorbed
		if f != target {
			_ = os.Remove(f)
		}
	}
	return merged, nil
}

func sharesID(ids []string, want map[string]bool) bool {
	for _, id := range ids {
		if want[id] {
			return true
		}
	}
	return false
}

func sortedKeysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (l *Library) knowledgeDir() string { return filepath.Join(l.Root, "knowledge") }

func (l *Library) pinPath(label string) string {
	return filepath.Join(l.knowledgeDir(), ".pins", sanitizeKey(label)+".yaml")
}

// AddToPin folds one route's facts into the named pin's running union and
// returns the union so far, plus the pin's committed key/vendor. It refuses to
// merge when the pin already holds a different device model (a conflict the
// caller surfaces) so one label cannot silently span two phones. A route with
// no key of its own inherits the pin's.
func (l *Library) AddToPin(label, vendor, key string, facts map[string]string) (p *Pin, conflict string, err error) {
	p = &Pin{Label: label, Facts: map[string]string{}}
	if b, rerr := os.ReadFile(l.pinPath(label)); rerr == nil {
		_ = yaml.Unmarshal(b, p)
		if p.Facts == nil {
			p.Facts = map[string]string{}
		}
	}
	if key == "" {
		key, vendor = p.Key, p.Vendor // inherit from the pin
	}
	if p.Key != "" && key != "" && p.Key != key {
		return p, p.Key, nil // different device under one label — do not merge
	}
	if p.Key == "" {
		p.Key, p.Vendor = key, vendor
	}
	p.Label = label
	for name, val := range facts {
		p.Facts[name] = val // last value wins; a variant change is rare within a session
	}
	if err := os.MkdirAll(filepath.Dir(l.pinPath(label)), 0o755); err != nil {
		return p, "", err
	}
	out, err := yaml.Marshal(p)
	if err != nil {
		return p, "", err
	}
	return p, "", os.WriteFile(l.pinPath(label), out, 0o644)
}

// Unpin discards a pin's session buffer.
func (l *Library) Unpin(label string) error {
	err := os.Remove(l.pinPath(label))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (l *Library) knowledgePath(vendor, key string) string {
	if vendor == "" {
		vendor = "unknown"
	}
	return filepath.Join(l.knowledgeDir(), sanitizeKey(vendor), sanitizeKey(key)+".yaml")
}

// Learn folds one recon's non-identifying facts into the store for a device,
// keyed by its stable model name (codename, else JTAG), as a matching set. It
// returns the human-readable changes — new fact values, or a new combination of
// already-seen ones — and writes nothing when the observation adds no new
// matching set.
func (l *Library) Learn(vendor, key string, learned map[string]string) (added []string, err error) {
	if key == "" || len(learned) == 0 {
		return nil, nil
	}
	path := l.knowledgePath(vendor, key)
	k := &Knowledge{Key: key, Vendor: vendor}
	if b, rerr := os.ReadFile(path); rerr == nil {
		_ = yaml.Unmarshal(b, k)
	}
	k.Key, k.Vendor = key, vendor

	// New (key=value) pairs are those in no existing observation.
	for name, val := range learned {
		if !anyObservationHas(k.Observations, name, val) {
			added = append(added, name+"="+val)
		}
	}
	// Keep the observation as a maximal set. A set already containing this one
	// makes it ambiguous: the same fields, seen without the extra ones, could be
	// that variant observed through a narrower vantage, or a different variant
	// that shares these fields but differs in the ones we did not see. We can
	// prove neither, so a subset spawns no set of its own (that would assert a
	// variant lacking the extra fields) and confirms none (that would assert it
	// is the larger one) — it simply adds nothing. Only a set that is not
	// contained in any existing one is new evidence of a distinct configuration.
	subsumed := false
	kept := k.Observations[:0]
	for _, o := range k.Observations {
		if subsetOf(learned, o) {
			subsumed = true
		}
		if properSubset(o, learned) {
			continue // learned supersedes this smaller set
		}
		kept = append(kept, o)
	}
	newSet := !subsumed
	if newSet {
		kept = append(kept, copyStringMap(learned))
	}
	if len(added) == 0 && !newSet {
		return nil, nil // nothing new, and no new correlation — leave the file be
	}
	k.Observations = kept
	sort.Strings(added)
	if newSet && len(added) == 0 {
		// Every value was seen before, but not together: the correlation is new.
		added = append(added, "(new matching set)")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if k.FirstSeen == "" {
		k.FirstSeen = now
	}
	k.LastLearned = now
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return added, err
	}
	out, err := yaml.Marshal(k)
	if err != nil {
		return added, err
	}
	return added, os.WriteFile(path, out, 0o644)
}

func anyObservationHas(obs []map[string]string, name, val string) bool {
	for _, o := range obs {
		if o[name] == val {
			return true
		}
	}
	return false
}

// subsetOf reports whether every pair of a is present in b with the same value.
func subsetOf(a, b map[string]string) bool {
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// properSubset is subsetOf without equality — a is strictly smaller than b.
func properSubset(a, b map[string]string) bool {
	return len(a) < len(b) && subsetOf(a, b)
}

func copyStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sanitizeKey(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			return r
		}
		return '_'
	}, strings.TrimSpace(s))
	if s == "" {
		return "unknown"
	}
	return s
}
