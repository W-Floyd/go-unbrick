// Package facts is a derivation graph over named data: providers declare what
// fact they can produce and from which other facts, and a planner chains them to
// reach a target, runs every reachable derivation, and cross-checks a fact that
// more than one path produced.
//
// The split is deliberate: typed at the edges (Fact keys, Get/Set, provider
// bodies), erased in the core (Bag, graph, planner). Go cannot hold a
// Provider[uint16] and a Provider[string] in one slice, so Provider is
// non-generic and names its edges as strings; the single type assertion in the
// whole package lives in Get.
//
// No vendor knowledge lives here. Vendors contribute providers and checks
// through their own seam.
package facts

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// Level ranks how far a value's origin can be trusted. It breaks ties for the
// value a report displays, and it is a property of the derivation, not of the
// datum — the same CID is Attested read from a package's signed manifest and
// merely Derived when reconstructed from a mutable device partition.
type Level int

const (
	// Reference is a vendor-claimed or community-collected table: useful, unattested.
	Reference Level = iota
	// Derived is computed from another fact or read from a mutable source.
	Derived
	// Attested is read from the artifact that defines it (a signed image, an OEM manifest).
	Attested
)

func (l Level) String() string {
	switch l {
	case Attested:
		return "attested"
	case Derived:
		return "derived"
	case Reference:
		return "reference"
	}
	return fmt.Sprintf("level(%d)", int(l))
}

// Fact is a typed key: a fact name carrying its value type at compile time.
// Keys are declared once per name (see keys.go) — two keys sharing a name with
// different T is the one footgun, and it is grep-obvious.
type Fact[T any] struct {
	name   string
	equal  func(a, b T) bool
	format func(T) string
}

// Opt tunes a key.
type Opt[T any] func(*Fact[T])

// Eq gives a key a comparison for verification, for values where == or a deep
// compare says the wrong thing (a cert chain compared as a fingerprint set).
func Eq[T any](f func(a, b T) bool) Opt[T] {
	return func(k *Fact[T]) { k.equal = f }
}

// Fmt gives a key a human rendering, so reports and --why print 0x0033 rather
// than 51 without the renderer knowing which fact it holds.
func Fmt[T any](f func(T) string) Opt[T] {
	return func(k *Fact[T]) { k.format = f }
}

// Key declares a fact key and binds the name to its type. The core declares the
// common set (keys.go); a vendor adds its own keys the same way, which is how
// the fact namespace grows without the core learning a vendor's formats.
//
// Declaring the same name twice with different types is the one way to defeat
// the typing — Get would silently miss on the other declaration's values — so it
// panics here instead, at init, where the duplicate is obvious.
func Key[T any](name string, opts ...Opt[T]) Fact[T] {
	k := Fact[T]{name: name}
	for _, o := range opts {
		o(&k)
	}
	var zero T
	t := reflect.TypeOf(&zero).Elem()
	registryMu.Lock()
	defer registryMu.Unlock()
	if prev, ok := registry[name]; ok && prev != t {
		panic(fmt.Sprintf("facts: key %q already declared as %s, redeclared as %s", name, prev, t))
	}
	registry[name] = t
	return k
}

var (
	registryMu sync.Mutex
	registry   = map[string]reflect.Type{}
)

// Declared lists every fact name a key exists for — the core's and whatever the
// linked vendors added — sorted.
func Declared() []string {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Name is the untyped key the graph and the Bag use.
func (f Fact[T]) Name() string { return f.name }

// sourcePrefix marks a leaf source (an input the recon already holds) as opposed
// to a derived fact. Sources are not cross-checked and are not shown as facts.
const sourcePrefix = "source:"

// IsSource reports whether a fact name is a leaf source rather than a derived fact.
func IsSource(name string) bool { return strings.HasPrefix(name, sourcePrefix) }

// Provenance is what a provider says about the value it is writing.
type Provenance struct {
	Source    string // human provenance, e.g. "flashfile.xml cid_value"
	Authority Level
}

// Value is one resolved value. Data is any at rest and is read back through the
// typed Get; nothing else asserts it.
type Value struct {
	Data      any
	Source    string
	Authority Level
}

// Step records one derivation the planner ran: which fact it produced, from
// what, and the value it wrote. It is what --why walks.
type Step struct {
	Fact   string
	Inputs []string
	Value  Value
}

// Bag holds every value produced for a fact, not just the winning one, so
// corroboration and disagreement are both visible.
type Bag struct {
	vals  map[string][]Value
	eq    map[string]func(a, b any) bool
	show  map[string]func(any) string
	trace map[string][]Step
}

// NewBag returns an empty Bag.
func NewBag() *Bag {
	return &Bag{
		vals:  map[string][]Value{},
		eq:    map[string]func(a, b any) bool{},
		show:  map[string]func(any) string{},
		trace: map[string][]Step{},
	}
}

// Set writes a value for f. Repeated writes accumulate; they do not overwrite.
func Set[T any](b *Bag, f Fact[T], v T, p Provenance) {
	name := f.name
	if _, ok := b.eq[name]; !ok && f.equal != nil {
		eq := f.equal
		b.eq[name] = func(x, y any) bool {
			a, ok1 := x.(T)
			c, ok2 := y.(T)
			return ok1 && ok2 && eq(a, c)
		}
	}
	if _, ok := b.show[name]; !ok && f.format != nil {
		fm := f.format
		b.show[name] = func(x any) string {
			a, ok := x.(T)
			if !ok {
				return fmt.Sprintf("%v", x)
			}
			return fm(a)
		}
	}
	b.vals[name] = append(b.vals[name], Value{Data: v, Source: p.Source, Authority: p.Authority})
}

// Get returns the authoritative value for f — the sole type assertion in the
// package. ok is false when the fact is absent, or (a declaration bug) when the
// stored value is not of f's type.
func Get[T any](b *Bag, f Fact[T]) (T, bool) {
	var zero T
	v, ok := b.Best(f.name)
	if !ok {
		return zero, false
	}
	d, ok := v.Data.(T)
	if !ok {
		return zero, false
	}
	return d, true
}

// GetAll returns every value held for f, in derivation order, skipping any whose
// stored type is not T. A provider whose source more than one input can satisfy
// — a package that carries two manifests, or a vbmeta.img beside a
// vbmeta_system.img — iterates these so it finds a usable one whatever order the
// members arrived in, rather than reading only the first and missing the rest.
func GetAll[T any](b *Bag, f Fact[T]) []T {
	vs := b.vals[f.name]
	out := make([]T, 0, len(vs))
	for _, v := range vs {
		if d, ok := v.Data.(T); ok {
			out = append(out, d)
		}
	}
	return out
}

// Has reports whether any value has been produced for a fact.
func (b *Bag) Has(name string) bool { return len(b.vals[name]) > 0 }

// HasAll reports whether every named fact is present.
func (b *Bag) HasAll(names []string) bool {
	for _, n := range names {
		if !b.Has(n) {
			return false
		}
	}
	return true
}

// Values returns every value produced for a fact, in the order they were derived
// (which, under the planner, is cheapest first).
func (b *Bag) Values(name string) []Value { return b.vals[name] }

// Names lists the facts the Bag holds, sorted.
func (b *Bag) Names() []string {
	out := make([]string, 0, len(b.vals))
	for n := range b.vals {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Best is the value a report displays: the highest authority, earliest derived.
func (b *Bag) Best(name string) (Value, bool) {
	vs := b.vals[name]
	if len(vs) == 0 {
		return Value{}, false
	}
	best := vs[0]
	for _, v := range vs[1:] {
		if v.Authority > best.Authority {
			best = v
		}
	}
	return best, true
}

// Agreeing lists the sources that produced a value equal to the winning one,
// the winner first. Agreement is not a finding — it is corroboration, and its
// count is the confidence a report can show.
func (b *Bag) Agreeing(name string) []string {
	best, ok := b.Best(name)
	if !ok {
		return nil
	}
	var out []string
	for _, v := range b.vals[name] {
		if b.Equal(name, v.Data, best.Data) {
			out = append(out, v.Source)
		}
	}
	return out
}

// Equal compares two values of a fact with the key's comparison, defaulting to
// a deep compare (which agrees with == for the scalar facts).
func (b *Bag) Equal(name string, x, y any) bool {
	if eq := b.eq[name]; eq != nil {
		return eq(x, y)
	}
	return reflect.DeepEqual(x, y)
}

// Show renders a value the way its key asked to be printed.
func (b *Bag) Show(name string, data any) string {
	if f := b.show[name]; f != nil {
		return f(data)
	}
	return fmt.Sprintf("%v", data)
}

// Trace returns the derivations recorded for a fact, in the order they ran.
func (b *Bag) Trace(name string) []Step { return b.trace[name] }

func (b *Bag) record(s Step) { b.trace[s.Fact] = append(b.trace[s.Fact], s) }

// Provider is one edge of the graph: it derives one fact from others. It is
// non-generic so a heterogeneous set shares a graph; its Derive body reads and
// writes the Bag through the typed Get/Set.
type Provider interface {
	Provides() string   // Fact.Name()
	Requires() []string // other facts / leaf sources it consumes
	Cost() int          // relative: a local parse is 1, a paced fastboot round trip 100
	Authority() Level
	Derive(in *Bag) (bool, error) // ok=false: this source does not carry the fact
}

// Rule is the ordinary Provider: a closure with its edges and price declared.
//
// Cost is relative — the planner only ever compares. The scale in use: local
// byte parse or catalog lookup 1, reading a zip member 5, a paced getvar or oem
// probe 100, an EDL/partition read 500.
type Rule struct {
	Out   string
	In    []string
	Price int
	Level Level
	Fn    func(*Bag) (bool, error)
}

func (r Rule) Provides() string             { return r.Out }
func (r Rule) Requires() []string           { return r.In }
func (r Rule) Cost() int                    { return r.Price }
func (r Rule) Authority() Level             { return r.Level }
func (r Rule) Derive(in *Bag) (bool, error) { return r.Fn(in) }

// Severity ranks a finding.
type Severity int

const (
	// Warn is a same-fact disagreement: both values are kept, authority picks the display.
	Warn Severity = iota
	// Error is a broken invariant between facts.
	Error
	// Info is a confirmation, not a problem — e.g. an integrity pass that matched.
	Info
)

func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case Info:
		return "info"
	default:
		return "warn"
	}
}

// Finding is a judgment about values — a conflict or a broken invariant — not a
// value, so it rides beside the Bag rather than in it.
type Finding struct {
	Severity Severity
	Facts    []string
	Message  string
	Values   []Value
}

// File is one file offered to the recognizers: the thing the command was
// pointed at, or a member found inside it.
type File struct {
	Name string // base name, as the container spells it
	Data []byte
	From string // provenance, e.g. "stock.zip flashfile.xml"
	// Top is set for the file the command names, false for a member. A source
	// that a package holds many of (every signed image) is a fact only when it is
	// the thing being examined; inside a container it is one of a crowd.
	Top bool
}

// Recognizer decides what a file *is* and sets the source facts it yields. It is
// what keeps ingestion content-driven: nothing asks a package for "flashfile.xml"
// by name, it asks every member what it can tell us. Returns the source facts it
// set, for the caller's trace.
type Recognizer func(b *Bag, f File) []string

// Recognize offers one file to every recognizer and returns everything set.
func Recognize(b *Bag, rs []Recognizer, f File) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r(b, f)...)
	}
	return out
}

// Check is a declared invariant between different facts (unlock salt == device
// UID, a signing CID that must match its region). Facts merely *expected* to
// differ are separate facts, not a check.
type Check interface {
	Reads() []string
	Verify(in *Bag) []Finding
}

// CheckFunc is the ordinary Check: a closure over the facts it inspects. A check
// marked Heavy runs only under Options.Verify — for one whose work is too costly
// for a default pass, like hashing every member of a multi-gigabyte package.
type CheckFunc struct {
	On    []string
	Heavy bool
	Fn    func(*Bag) []Finding
}

func (c CheckFunc) Reads() []string          { return c.On }
func (c CheckFunc) Verify(in *Bag) []Finding { return c.Fn(in) }
func (c CheckFunc) VerifyOnly() bool         { return c.Heavy }

// VerifyGated is an optional Check capability: a check that declares itself too
// heavy to run unless the caller opted into verification. The planner skips such
// a check outside Options.Verify.
type VerifyGated interface{ VerifyOnly() bool }

// Result is a resolution: everything derived, plus what is wrong with it.
type Result struct {
	Bag      *Bag
	Findings []Finding
}
