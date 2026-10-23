// Package recognize is the one registry a file's content-sniffing recognizers
// go through, replacing what used to be the same hand-copied if/else chain
// repeated across recon's short label, its one-line summary, and its full
// report: each recognizer is written once, registered once, and every caller
// asks the registry instead of re-implementing the chain.
//
// This does not replace internal/filetype.Detect, which stays as it is: one
// neutral, self-contained switch over magic bytes for cross-vendor formats
// (zip, ELF, ext4, ...), with no duplication problem of its own. What belongs
// here is the second tier on top of it -- a vendor's own container format, a
// credentials file identified by name and shape, a key list recognized by its
// armor -- the layer that used to be copied by hand into typeLabel, summarize,
// and recon's full-report fallback separately, with no guarantee the three
// stayed in the same order or agreed on what a file was.
package recognize

// Recognizer claims files by content (and optionally name) and knows how to
// label and report on what it claims. A recognizer that needs context beyond
// name/head/data (a device catalog, say) gets it through its own package-level
// hook, the way pkg/analysis's OpenRoot/TypeLabel hooks already work -- kept
// out of this interface so it stays usable without that context wired up.
type Recognizer interface {
	// Name is this recognizer's key in pkg/analysis/cache's Versions registry:
	// bump cache.Versions[r.Name()] whenever Claims, Label, Summary or Report's
	// behavior changes for bytes it would already have been asked about.
	Name() string
	// Claims reports whether this recognizer owns the file, from its head
	// bytes and name (name is "" where no filename is in scope -- only a
	// content-shape check can still match). Cheap: a registry tries every
	// recognizer, in order, until one claims it.
	Claims(name string, head []byte) bool
	// Label is a short, one-line type name (a listing's label column, recon's
	// "Type:" line). Only ever called after Claims returned true for the same
	// (name, head).
	Label(name string, head []byte) string
	// Summary is one further line of inline detail, recon's " — ..." style;
	// "" when there is nothing beyond Label worth saying. data is the whole
	// file when available, nil when only head was read (a listing's shallow
	// probe) -- a Summary that needs the whole file returns "" on nil data
	// rather than guessing from a truncated head.
	Summary(name string, head, data []byte) string
	// Report is the fuller, multi-line body recon prints under Label and
	// Summary; nil for a recognizer with nothing more to add there. path is
	// the file's own path, for a recognizer that wants to re-read it itself
	// (as the fuller report sometimes needs more than head/data provide);
	// data is the whole file when available, nil when only head was read.
	Report(path, name string, head, data []byte) []string
}

// Registry is an ordered list of Recognizers, tried in registration order: the
// first to Claims a file wins. A library consumer builds its own with
// NewRegistry instead of using Default, or adds to Default to extend this
// tool's own recognizers rather than replace them.
type Registry struct {
	recognizers []Recognizer
}

// NewRegistry is an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds r after whatever is already registered. Order is precedence:
// register a narrower, more specific recognizer before a broader one it could
// otherwise be shadowed by.
func (reg *Registry) Register(r Recognizer) { reg.recognizers = append(reg.recognizers, r) }

// Find is the first registered Recognizer that Claims the file, if any.
func (reg *Registry) Find(name string, head []byte) (Recognizer, bool) {
	for _, r := range reg.recognizers {
		if r.Claims(name, head) {
			return r, true
		}
	}
	return nil, false
}

// All is every registered Recognizer, in registration order.
func (reg *Registry) All() []Recognizer {
	out := make([]Recognizer, len(reg.recognizers))
	copy(out, reg.recognizers)
	return out
}

// Names is every registered Recognizer's Name, in registration order -- what a
// pkg/analysis/cache.Domain built over this registry depends on: construct one
// with cache.Domain{Name: "...", Members: registry.Names()} so adding a
// recognizer here is automatically covered by that Domain's invalidation,
// with no second list to remember to update.
func (reg *Registry) Names() []string {
	names := make([]string, len(reg.recognizers))
	for i, r := range reg.recognizers {
		names[i] = r.Name()
	}
	return names
}

// Default is the registry go-unbrick's own CLI wires its recognizers into
// (see cmd_recon_registry.go), in the exact order recon has always tried them.
var Default = NewRegistry()
