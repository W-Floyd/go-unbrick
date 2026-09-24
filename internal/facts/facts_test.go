package facts

import (
	"strings"
	"testing"
)

// Fake facts, so the core is tested without any vendor's meaning attached.
var (
	tSrcA  = Key[string]("test:src.a")
	tSrcB  = Key[string]("test:src.b")
	tProbe = Key[string]("test:src.probe")
	tMid   = Key[int]("test:mid")
	tLeaf  = Key[string]("test:leaf")
)

// constant derives out from in, recording which rule ran.
func constant[T any](out Fact[T], in Fact[string], price int, level Level, source string, v T, ran *[]string) Rule {
	return Rule{
		Out: out.Name(), In: []string{in.Name()}, Price: price, Level: level,
		Fn: func(b *Bag) (bool, error) {
			*ran = append(*ran, source)
			Set(b, out, v, Provenance{Source: source, Authority: level})
			return true, nil
		},
	}
}

func bagWith(f Fact[string], v string) *Bag {
	b := NewBag()
	Set(b, f, v, Provenance{Source: "given", Authority: Attested})
	return b
}

func TestResolveTakesCheapestPath(t *testing.T) {
	var ran []string
	g := New([]Provider{
		constant(tMid, tProbe, 100, Attested, "probe", 7, &ran),
		constant(tMid, tSrcA, 1, Attested, "parse", 7, &ran),
	}, nil)
	b := bagWith(tSrcA, "x")
	Set(b, tProbe, "device", Provenance{Source: "given", Authority: Attested})

	if _, err := g.Resolve(b, tMid.Name(), Options{}); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 1 || ran[0] != "parse" {
		t.Fatalf("ran %v, want only the cheap rule", ran)
	}
	if v, ok := Get(b, tMid); !ok || v != 7 {
		t.Fatalf("mid = %v %v", v, ok)
	}
}

func TestResolveChains(t *testing.T) {
	var ran []string
	// leaf ← mid ← src.a: the planner must run them in dependency order.
	chain := Rule{
		Out: tLeaf.Name(), In: []string{tMid.Name()}, Price: 1, Level: Derived,
		Fn: func(b *Bag) (bool, error) {
			v, ok := Get(b, tMid)
			if !ok {
				t.Error("chain ran before its input existed")
			}
			ran = append(ran, "chain")
			Set(b, tLeaf, strings.Repeat("!", v), Provenance{Source: "chain", Authority: Derived})
			return true, nil
		},
	}
	g := New([]Provider{chain, constant(tMid, tSrcA, 1, Attested, "parse", 3, &ran)}, nil)
	b := bagWith(tSrcA, "x")
	if _, err := g.Resolve(b, tLeaf.Name(), Options{}); err != nil {
		t.Fatal(err)
	}
	if v, _ := Get(b, tLeaf); v != "!!!" {
		t.Fatalf("leaf = %q", v)
	}
	if len(ran) != 2 || ran[0] != "parse" {
		t.Fatalf("order %v", ran)
	}
}

func TestResolveUnreachable(t *testing.T) {
	g := New([]Provider{constant(tMid, tSrcB, 1, Attested, "parse", 1, new([]string))}, nil)
	if _, err := g.Resolve(bagWith(tSrcA, "x"), tMid.Name(), Options{}); err == nil {
		t.Fatal("want an error when nothing reaches the target")
	}
}

func TestResolveAllDisagreementKeepsBothAndPicksAuthority(t *testing.T) {
	var ran []string
	g := New([]Provider{
		constant(tMid, tSrcA, 1, Attested, "package manifest", 51, &ran),
		constant(tMid, tSrcB, 1, Derived, "device partition", 50, &ran),
	}, nil)
	b := bagWith(tSrcA, "x")
	Set(b, tSrcB, "y", Provenance{Source: "given", Authority: Attested})

	res := g.ResolveAll(b, Options{})
	if len(b.Values(tMid.Name())) != 2 {
		t.Fatalf("both values should be kept, got %v", b.Values(tMid.Name()))
	}
	if v, _ := Get(b, tMid); v != 51 {
		t.Fatalf("authority should pick the attested value, got %d", v)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != Warn ||
		!strings.Contains(res.Findings[0].Message, "disagrees") {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if got := b.Agreeing(tMid.Name()); len(got) != 1 || got[0] != "package manifest" {
		t.Fatalf("agreeing = %v", got)
	}
}

func TestResolveAllAgreementIsNotAFinding(t *testing.T) {
	var ran []string
	g := New([]Provider{
		constant(tMid, tSrcA, 1, Attested, "one", 51, &ran),
		constant(tMid, tSrcB, 1, Derived, "two", 51, &ran),
	}, nil)
	b := bagWith(tSrcA, "x")
	Set(b, tSrcB, "y", Provenance{Source: "given", Authority: Attested})

	res := g.ResolveAll(b, Options{})
	if len(res.Findings) != 0 {
		t.Fatalf("agreement is corroboration, not a finding: %+v", res.Findings)
	}
	if got := b.Agreeing(tMid.Name()); len(got) != 2 {
		t.Fatalf("both sources should corroborate: %v", got)
	}
}

func TestResolveAllSkipsExpensiveRedundantPath(t *testing.T) {
	var ran []string
	probe := constant(tMid, tProbe, 100, Attested, "probe", 9, &ran)
	local := constant(tMid, tSrcA, 1, Attested, "parse", 7, &ran)
	b := func() *Bag {
		b := bagWith(tSrcA, "x")
		Set(b, tProbe, "device", Provenance{Source: "given", Authority: Attested})
		return b
	}

	ran = nil
	New([]Provider{probe, local}, nil).ResolveAll(b(), Options{})
	if len(ran) != 1 || ran[0] != "parse" {
		t.Fatalf("without --verify the probe should not run: %v", ran)
	}

	ran = nil
	res := New([]Provider{probe, local}, nil).ResolveAll(b(), Options{Verify: true})
	if len(ran) != 2 {
		t.Fatalf("--verify should run the redundant path: %v", ran)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("the redundant path disagrees; want one finding, got %+v", res.Findings)
	}
}

func TestChecksSeeOnlyWhatTheyRead(t *testing.T) {
	var ran []string
	called := 0
	chk := CheckFunc{
		On: []string{tMid.Name(), tLeaf.Name()},
		Fn: func(b *Bag) []Finding {
			called++
			return []Finding{{Severity: Error, Facts: []string{tMid.Name()}, Message: "invariant broken"}}
		},
	}
	// tLeaf is never derived, so the check must not run.
	g := New([]Provider{constant(tMid, tSrcA, 1, Attested, "parse", 1, &ran)}, []Check{chk})
	if res := g.ResolveAll(bagWith(tSrcA, "x"), Options{}); len(res.Findings) != 0 || called != 0 {
		t.Fatalf("check ran without its inputs: called=%d findings=%+v", called, res.Findings)
	}

	b := bagWith(tSrcA, "x")
	Set(b, tLeaf, "here", Provenance{Source: "given", Authority: Attested})
	res := g.ResolveAll(b, Options{})
	if called != 1 || len(res.Findings) != 1 || res.Findings[0].Severity != Error {
		t.Fatalf("called=%d findings=%+v", called, res.Findings)
	}
}

func TestDeriveErrorBecomesAFinding(t *testing.T) {
	g := New([]Provider{Rule{
		Out: tMid.Name(), In: []string{tSrcA.Name()}, Price: 1, Level: Attested,
		Fn: func(b *Bag) (bool, error) { return false, errTest },
	}}, nil)
	res := g.ResolveAll(bagWith(tSrcA, "x"), Options{})
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Message, "boom") {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

var errTest = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }

func TestExplainShowsChainAndCorroboration(t *testing.T) {
	var ran []string
	g := New([]Provider{
		constant(tMid, tSrcA, 1, Attested, "package manifest", 51, &ran),
		constant(tMid, tSrcB, 1, Derived, "device partition", 50, &ran),
	}, nil)
	b := bagWith(tSrcA, "x")
	Set(b, tSrcB, "y", Provenance{Source: "given", Authority: Attested})
	g.ResolveAll(b, Options{})

	out := strings.Join(Explain(b, tMid.Name()), "\n")
	for _, want := range []string{"package manifest", "attested", "from test:src.a", "50", "disagrees"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain missing %q:\n%s", want, out)
		}
	}
}

func TestKeyRedeclaredWithAnotherTypePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a name bound to two types must panic at declaration")
		}
	}()
	_ = Key[int]("test:src.a")
}

func TestGetOnWrongTypeIsNotAHit(t *testing.T) {
	b := NewBag()
	Set(b, tMid, 3, Provenance{Source: "s"})
	// Reading through a same-named key of another type cannot happen (Key panics),
	// but a hand-built Value can still be mistyped; Get must miss, not panic.
	b.vals[tMid.Name()] = []Value{{Data: "three", Source: "s"}}
	if _, ok := Get(b, tMid); ok {
		t.Fatal("want a miss")
	}
}

func TestFormatterRendersThroughShow(t *testing.T) {
	k := Key[uint16]("test:hexed", Fmt(func(v uint16) string { return "0x" + strings.ToUpper(hex4(v)) }))
	b := NewBag()
	Set(b, k, 51, Provenance{Source: "s"})
	v, _ := b.Best(k.Name())
	if got := b.Show(k.Name(), v.Data); got != "0x0033" {
		t.Fatalf("show = %q", got)
	}
}

func hex4(v uint16) string {
	const d = "0123456789abcdef"
	return string([]byte{d[v>>12&0xf], d[v>>8&0xf], d[v>>4&0xf], d[v&0xf]})
}
