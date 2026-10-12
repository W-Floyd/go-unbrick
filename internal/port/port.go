package port

import (
	"fmt"
	"sort"
	"sync"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
)

// An Emitter turns what a stock package says into one distribution's
// packaging: its device description, its packaging files, and findings of its
// own about the package. Everything a distribution does not decide is in
// Package, so supporting another distribution is another Emitter, registered
// here, with no change to how the package is read.
type Emitter interface {
	// ID is what a user names it by ("nura"); lower case.
	ID() string
	// Title is its display name.
	Title() string
	// Emit builds the distribution's bundle from the package.
	Emit(p Package, o Options) (*Bundle, error)
}

// Options are what an Emitter may consult beyond the package.
type Options struct {
	// Catalog is the reference data (distribution packaging conventions, parts
	// tables); nil means none.
	Catalog *catalog.Catalog
}

// Bundle is what an Emitter produces.
type Bundle struct {
	// Files are the distribution's files by path relative to the output
	// directory.
	Files map[string][]byte
	// Report are markdown sections for the hardware report: the Emitter's own
	// findings (for example, which firmware its mechanism can supply).
	Report []string
	// Notes are one-line messages for the person running the tool.
	Notes []string
}

var (
	mu       sync.Mutex
	emitters = map[string]Emitter{}
)

// Register adds an Emitter. Registering an ID twice panics: that is a
// programming error, found at init.
func Register(e Emitter) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := emitters[e.ID()]; dup {
		panic(fmt.Sprintf("port: emitter %q registered twice", e.ID()))
	}
	emitters[e.ID()] = e
}

// Lookup returns the Emitter registered under id.
func Lookup(id string) (Emitter, bool) {
	mu.Lock()
	defer mu.Unlock()
	e, ok := emitters[id]
	return e, ok
}

// IDs lists the registered distributions, sorted.
func IDs() []string {
	mu.Lock()
	defer mu.Unlock()
	var out []string
	for id := range emitters {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
