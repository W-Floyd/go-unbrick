package analysis

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// diffProfile is `diff --profile`: where the wall time went. Phases and member
// times are inclusive (a container's time includes the reads inside it); the
// SFTP line is the network time alone, which they all contain.
type diffProfile struct {
	mu      sync.Mutex
	start   time.Time
	phases  map[string]time.Duration
	expand  map[string]time.Duration
	expands map[string]int
	members []profItem
	sftpN   int
	sftpB   int64
	sftpT   time.Duration
}

type profItem struct {
	what string
	d    time.Duration
}

var dprof *diffProfile

func startDiffProfile() {
	p := &diffProfile{start: time.Now(), phases: map[string]time.Duration{}, expand: map[string]time.Duration{}, expands: map[string]int{}}
	dprof = p
	infile.OnSSHRead = func(n int, d time.Duration) {
		p.mu.Lock()
		p.sftpN++
		p.sftpB += int64(n)
		p.sftpT += d
		p.mu.Unlock()
	}
	carve.OnExpand = func(kind, name string, d time.Duration) {
		if d >= time.Second {
			fmt.Fprintf(os.Stderr, "profile: listing %s (%s) took %s\n", name, kind, d.Round(time.Millisecond))
		}
		p.mu.Lock()
		p.expand[kind] += d
		p.expands[kind]++
		p.mu.Unlock()
	}
}

// logf says something live on stderr. Nil-safe.
func (p *diffProfile) logf(format string, args ...any) {
	if p == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "profile: "+format+"\n", args...)
}

// phase times a stretch of the run; call the result when it ends. Nil-safe.
func (p *diffProfile) phase(name string) func() {
	if p == nil {
		return func() {}
	}
	t := time.Now()
	return func() {
		p.mu.Lock()
		p.phases[name] += time.Since(t)
		p.mu.Unlock()
	}
}

// member times one member's comparison. Nil-safe.
func (p *diffProfile) member(what string) func() {
	if p == nil {
		return func() {}
	}
	t := time.Now()
	return func() {
		p.mu.Lock()
		p.members = append(p.members, profItem{what, time.Since(t)})
		p.mu.Unlock()
	}
}

func (p *diffProfile) report() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w := os.Stderr
	fmt.Fprintf(w, "\nprofile: %s total\n", time.Since(p.start).Round(time.Millisecond))
	byTime := func(m map[string]time.Duration) []string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Slice(ks, func(i, j int) bool { return m[ks[i]] > m[ks[j]] })
		return ks
	}
	fmt.Fprintln(w, "  phases (inclusive):")
	for _, k := range byTime(p.phases) {
		fmt.Fprintf(w, "    %-22s %s\n", k, p.phases[k].Round(time.Millisecond))
	}
	fmt.Fprintln(w, "  listing members, by container kind (inclusive):")
	for _, k := range byTime(p.expand) {
		fmt.Fprintf(w, "    %-22s %s  (%d)\n", k, p.expand[k].Round(time.Millisecond), p.expands[k])
	}
	rate := 0.0
	if p.sftpT > 0 {
		rate = float64(p.sftpB) / p.sftpT.Seconds() / (1 << 20)
	}
	fmt.Fprintf(w, "  sftp: %d reads, %s, %s summed over reads (%.1f MiB/s per read)\n",
		p.sftpN, humanBytes(p.sftpB), p.sftpT.Round(time.Millisecond), rate)
	sort.Slice(p.members, func(i, j int) bool { return p.members[i].d > p.members[j].d })
	fmt.Fprintln(w, "  slowest members (inclusive):")
	for i, m := range p.members {
		if i == 12 {
			break
		}
		fmt.Fprintf(w, "    %8s  %s\n", m.d.Round(time.Millisecond), m.what)
	}
}
