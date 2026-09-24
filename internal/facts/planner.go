package facts

import (
	"fmt"
	"sort"
	"strings"
)

// Graph is a set of providers (edges) and checks. Facts are the nodes: a
// provider's Requires are its inputs, its Provides the node it reaches.
type Graph struct {
	providers []Provider
	checks    []Check
}

// New builds a graph. Providers are ordered cheapest first, so a fact reachable
// both locally and through a probe takes the local path.
func New(providers []Provider, checks []Check) *Graph {
	ps := append([]Provider(nil), providers...)
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Cost() != ps[j].Cost() {
			return ps[i].Cost() < ps[j].Cost()
		}
		return ps[i].Provides() < ps[j].Provides()
	})
	return &Graph{providers: ps, checks: checks}
}

// Providers returns the graph's edges, cheapest first.
func (g *Graph) Providers() []Provider { return g.providers }

// Options tunes a resolution.
type Options struct {
	// Verify runs redundant paths for their cross-check value, including the ones
	// a budget would otherwise skip. Without it, a fact already known locally is
	// not re-derived through an expensive probe.
	Verify bool
	// Budget is the cost above which a provider counts as expensive. Zero means
	// DefaultBudget.
	Budget int
}

// DefaultBudget draws the line between reading what you already have (a parse, a
// catalog lookup, a zip member) and going out to the device for it.
const DefaultBudget = 10

func (o Options) budget() int {
	if o.Budget <= 0 {
		return DefaultBudget
	}
	return o.Budget
}

// ResolveAll runs every provider whose inputs are satisfied, cheapest first, to
// a fixpoint — everything reachable from what the Bag already holds — then
// cross-checks and runs the registered checks.
func (g *Graph) ResolveAll(b *Bag, opts Options) *Result {
	res := &Result{Bag: b}
	done := make([]bool, len(g.providers))
	for {
		progress := false
		for i, p := range g.providers {
			if done[i] || !b.HasAll(p.Requires()) {
				continue
			}
			// An expensive path is only worth walking for a fact we do not already
			// have, or when asked to verify.
			if p.Cost() > opts.budget() && b.Has(p.Provides()) && !opts.Verify {
				done[i] = true
				continue
			}
			done[i] = true
			progress = true
			g.run(b, p, res)
		}
		if !progress {
			return g.finish(b, res, opts)
		}
	}
}

// Resolve derives one fact by the cheapest satisfiable chain, running only the
// providers that chain needs. It errors when no chain reaches the target from
// what the Bag holds.
func (g *Graph) Resolve(b *Bag, target string, opts Options) (*Result, error) {
	res := &Result{Bag: b}
	if b.Has(target) && !opts.Verify {
		return g.finish(b, res, opts), nil
	}
	plan, ok := g.plan(b, target, opts)
	if !ok {
		return nil, fmt.Errorf("facts: no path to %s from %s", target, strings.Join(b.Names(), ", "))
	}
	for _, p := range plan {
		if !b.HasAll(p.Requires()) {
			continue // an earlier step declined (ok=false); the chain is broken
		}
		g.run(b, p, res)
	}
	if !b.Has(target) {
		return g.finish(b, res, opts), fmt.Errorf("facts: %s not derivable: a step on the cheapest path had nothing to say", target)
	}
	return g.finish(b, res, opts), nil
}

// run executes one provider and records the derivation for --why.
func (g *Graph) run(b *Bag, p Provider, res *Result) {
	before := len(b.Values(p.Provides()))
	ok, err := p.Derive(b)
	if err != nil {
		res.Findings = append(res.Findings, Finding{
			Severity: Warn,
			Facts:    []string{p.Provides()},
			Message:  fmt.Sprintf("deriving %s failed: %v", p.Provides(), err),
		})
		return
	}
	if !ok {
		return
	}
	for _, v := range b.Values(p.Provides())[before:] {
		b.record(Step{Fact: p.Provides(), Inputs: p.Requires(), Value: v})
	}
}

// finish adds the same-fact conflicts and the declared checks.
func (g *Graph) finish(b *Bag, res *Result, opts Options) *Result {
	res.Findings = append(res.Findings, conflicts(b)...)
	for _, c := range g.checks {
		if !b.HasAll(c.Reads()) {
			continue
		}
		if vg, ok := c.(VerifyGated); ok && vg.VerifyOnly() && !opts.Verify {
			continue
		}
		res.Findings = append(res.Findings, c.Verify(b)...)
	}
	return res
}

// conflicts compares the values held for each fact. Different facts that are
// expected to differ are not compared — they are different facts.
func conflicts(b *Bag) []Finding {
	var out []Finding
	for _, name := range b.Names() {
		// A source is an input, not a claim about the device. A package that
		// carries two manifests or two vbmeta partitions holds two inputs of one
		// kind, which is not a contradiction — any real disagreement surfaces on
		// the facts *derived* from them, which is where it means something.
		if strings.HasPrefix(name, sourcePrefix) {
			continue
		}
		vs := b.Values(name)
		if len(vs) < 2 {
			continue
		}
		best, _ := b.Best(name)
		var odd []Value
		ambiguous := false
		for _, v := range vs {
			if b.Equal(name, v.Data, best.Data) {
				continue
			}
			odd = append(odd, v)
			if v.Authority == best.Authority {
				ambiguous = true
			}
		}
		if len(odd) == 0 {
			continue
		}
		parts := make([]string, 0, len(odd)+1)
		parts = append(parts, fmt.Sprintf("%s [%s]", b.Show(name, best.Data), best.Source))
		for _, v := range odd {
			parts = append(parts, fmt.Sprintf("%s [%s]", b.Show(name, v.Data), v.Source))
		}
		msg := fmt.Sprintf("%s disagrees: %s", name, strings.Join(parts, " vs "))
		if ambiguous {
			msg += " — equal authority, genuinely ambiguous"
		} else {
			msg += fmt.Sprintf(" — showing the %s value", best.Authority)
		}
		out = append(out, Finding{
			Severity: Warn,
			Facts:    []string{name},
			Message:  msg,
			Values:   append([]Value{best}, odd...),
		})
	}
	return out
}

// plan returns the providers of the cheapest chain from what the Bag holds to
// target, in the order they must run. Costs are relaxed to a fixpoint (the
// graphs are tiny; a provider is a hyperedge, so this is Bellman-Ford over the
// sum of its inputs rather than plain Dijkstra).
func (g *Graph) plan(b *Bag, target string, opts Options) ([]Provider, bool) {
	dist := map[string]int{}
	via := map[string]Provider{}
	for _, n := range b.Names() {
		dist[n] = 0
	}
	for round := 0; round <= len(g.providers); round++ {
		changed := false
		for _, p := range g.providers {
			if p.Cost() > opts.budget() && !opts.Verify && b.Has(p.Provides()) {
				continue
			}
			cost := p.Cost()
			ok := true
			for _, r := range p.Requires() {
				d, have := dist[r]
				if !have {
					ok = false
					break
				}
				cost += d
			}
			if !ok {
				continue
			}
			if d, have := dist[p.Provides()]; have && d <= cost {
				continue
			}
			dist[p.Provides()] = cost
			via[p.Provides()] = p
			changed = true
		}
		if !changed {
			break
		}
	}
	if _, ok := dist[target]; !ok {
		return nil, false
	}
	var out []Provider
	seen := map[string]bool{}
	var walk func(string)
	walk = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		p := via[name]
		if p == nil { // a leaf the Bag already holds
			return
		}
		for _, r := range p.Requires() {
			walk(r)
		}
		out = append(out, p)
	}
	walk(target)
	return out, true
}

// Explain renders how a fact was reached: the winning value, the chain behind
// it, and every source that corroborates or contradicts it. This is --why.
func Explain(b *Bag, name string) []string {
	best, ok := b.Best(name)
	if !ok {
		return []string{fmt.Sprintf("%s: not known", name)}
	}
	out := []string{fmt.Sprintf("%s = %s — %s [%s]", name, b.Show(name, best.Data), best.Source, best.Authority)}
	out = append(out, chain(b, name, "  ", map[string]bool{})...)
	for _, v := range b.Values(name) {
		if v.Source == best.Source && b.Equal(name, v.Data, best.Data) {
			continue
		}
		note := "disagrees"
		if b.Equal(name, v.Data, best.Data) {
			note = "agrees"
		}
		out = append(out, fmt.Sprintf("  %s — %s [%s, %s]", b.Show(name, v.Data), v.Source, v.Authority, note))
	}
	return out
}

// chain walks the recorded derivations backwards, one indent per hop.
func chain(b *Bag, name, indent string, seen map[string]bool) []string {
	if seen[name] {
		return nil
	}
	seen[name] = true
	var out []string
	for _, s := range b.Trace(name) {
		for _, in := range s.Inputs {
			// A leaf source is not a step in the derivation — it is the raw input,
			// and a source may hold several members (two vbmeta partitions, two
			// manifests) of which Best is an arbitrary one. The value's own
			// provenance already names where it came from, so expanding the source
			// here would only add a redundant, possibly wrong-member line.
			if IsSource(in) {
				continue
			}
			v, ok := b.Best(in)
			if !ok {
				continue
			}
			out = append(out, fmt.Sprintf("%sfrom %s = %s [%s]", indent, in, b.Show(in, v.Data), v.Source))
			out = append(out, chain(b, in, indent+"  ", seen)...)
		}
	}
	return out
}
