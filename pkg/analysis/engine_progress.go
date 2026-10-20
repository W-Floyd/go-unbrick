package analysis

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// diffProg is diff's status line on stderr: a bar of members compared out of
// those found so far (the total grows as containers are opened), the bytes
// read, and what it is on. Only drawn on a terminal, so piped output stays
// clean.
type diffProg struct {
	mu      sync.Mutex
	on      bool
	phase   string // what the run is doing: listing, comparing, matching renames
	unit    string // what members counts: "files", "removed files"
	label   string
	members int
	total   int
	bytes   int64
	last    time.Time
}

var dprog diffProg

func (p *diffProg) start() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.on = !diffQuiet && term.IsTerminal(int(os.Stderr.Fd()))
	p.phase, p.unit = "listing", ""
	p.label, p.members, p.total, p.bytes = "", 0, 0, 0
}

// begin starts a phase counting total units of unit (0 when not countable, or
// when the total is found as it goes). Bytes hashed carry across phases.
func (p *diffProg) begin(phase, unit string, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phase, p.unit, p.total, p.members, p.label = phase, unit, total, 0, ""
	p.draw(true)
}

// found adds n members to the total.
func (p *diffProg) found(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.total += n
}

// at names what is being worked on and counts a member finished.
func (p *diffProg) at(label string, done bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.label = label
	if done {
		p.members++
	}
	p.draw(true)
}

func (p *diffProg) add(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bytes += int64(n)
	p.draw(false)
}

const barWidth = 24

// draw repaints at most every 100ms unless forced by a new label.
func (p *diffProg) draw(force bool) {
	if !p.on || (!force && time.Since(p.last) < 100*time.Millisecond) {
		return
	}
	p.last = time.Now()
	head := p.phase + "  "
	if p.total > 0 {
		filled := min(barWidth, barWidth*p.members/p.total)
		head += fmt.Sprintf("[%s%s] %d/%d %s  ",
			strings.Repeat("█", filled), strings.Repeat("░", barWidth-filled), p.members, p.total, p.unit)
	}
	if p.bytes > 0 {
		head += humanBytes(p.bytes) + " hashed  "
	}
	label := p.label
	if w, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil {
		// Leave the last column free so the line never wraps.
		if room := w - 1 - len([]rune(head)); room < len([]rune(label)) {
			r := []rune(label)
			if room > 1 {
				label = "…" + string(r[len(r)-room+1:])
			} else {
				label = ""
			}
		}
	}
	fmt.Fprintf(os.Stderr, "\r\x1b[K%s%s", head, label)
}

// clear wipes the status line so stdout can print; the next update redraws it.
func (p *diffProg) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.on {
		fmt.Fprint(os.Stderr, "\r\x1b[K")
	}
}

func (p *diffProg) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.on {
		fmt.Fprint(os.Stderr, "\r\x1b[K")
		p.on = false
	}
}

type progReader struct{ r io.Reader }

func (p progReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	dprog.add(n)
	return n, err
}

// diffQuiet keeps the status line off the terminal, for a full-screen viewer
// that draws the same information itself (see status).
var diffQuiet bool

// status is what the comparison is doing, in a line, for a viewer to show.
func (p *diffProg) status() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.phase == "" {
		return ""
	}
	s := p.phase
	if p.total > 0 {
		s += fmt.Sprintf(" %d/%d %s", p.members, p.total, p.unit)
	}
	if p.bytes > 0 {
		s += "  " + humanBytes(p.bytes) + " hashed"
	}
	if p.label != "" {
		s += "  " + p.label
	}
	return s
}
