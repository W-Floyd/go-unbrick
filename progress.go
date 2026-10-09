package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"

	"github.com/W-Floyd/go-unbrick/internal/fastboot"
	"github.com/W-Floyd/go-unbrick/internal/infile"
)

// What a recon draws on stderr while it works: a step bar where the work is
// countable, a spinner where it is one opaque wait. Both clear themselves
// before the report, and neither is drawn off a terminal, where the cursor
// codes are just noise in a log.

// stderrIsTTY gates every transient status line.
var stderrIsTTY = func() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

// barSink drives a step bar; it satisfies every package's progress interface
// (Begin/Describe/Advance). A nil *barSink draws nothing, so callers pass one
// unconditionally.
//
// While an http(s) input is being read, the label carries the fetch rate, and a
// ticker redraws it so a long fetch inside one step still moves. Clear pauses
// the ticker until the next Describe or Advance, so it never draws over a
// caller's print.
type barSink struct {
	bar    *progressbar.ProgressBar
	mu     sync.Mutex
	label  string
	paused bool
}

// newBar is a step bar, or nil off a terminal.
func newBar() *barSink {
	if !stderrIsTTY {
		return nil
	}
	return &barSink{}
}

func (b *barSink) Begin(total int) {
	if b == nil || total <= 0 {
		return
	}
	// The total is fixed once set: sub-steps relabel via Describe without
	// advancing, so the bar only moves forward. The last Advance reaches max
	// and ClearOnFinish wipes the line before the report.
	bar := progressbar.NewOptions(total,
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetDescription("querying device"),
		progressbar.OptionShowDescriptionAtLineEnd(), // bar first, label after it
		progressbar.OptionSetWidth(24),
		progressbar.OptionClearOnFinish(),
	)
	b.mu.Lock()
	b.bar, b.label, b.paused = bar, "querying device", false
	b.mu.Unlock()
	go b.tick(bar)
}

func (b *barSink) tick(bar *progressbar.ProgressBar) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		b.mu.Lock()
		if b.bar != bar || bar.IsFinished() {
			b.mu.Unlock()
			return
		}
		if !b.paused && infile.Fetched() > 0 {
			b.bar.Describe(b.label + netStatus())
		}
		b.mu.Unlock()
	}
}

func (b *barSink) Describe(label string) {
	if b != nil && b.bar != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.label, b.paused = label, false
		b.bar.Describe(label + netStatus())
	}
}

func (b *barSink) Advance() {
	if b != nil && b.bar != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.paused = false
		_ = b.bar.Add(1)
	}
}

// Clear wipes the bar mid-run, so a caller can print; the next Describe or
// Advance redraws it below whatever was printed.
func (b *barSink) Clear() {
	if b != nil && b.bar != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.paused = true
		clearProgress()
	}
}

// netRate holds recent samples of infile.Fetched for netStatus's rate.
var netRate struct {
	mu      sync.Mutex
	samples []netSample
}

type netSample struct {
	at time.Time
	n  int64
}

// netStatus is " · 42.1 MiB fetched · 6.3 MiB/s" once anything has come over
// the network, "" otherwise. The rate spans the last two seconds, so it drops
// away while a fetched blob is decompressed.
func netStatus() string {
	n := infile.Fetched()
	if n == 0 {
		return ""
	}
	now := time.Now()
	netRate.mu.Lock()
	s := append(netRate.samples, netSample{now, n})
	for len(s) > 1 && now.Sub(s[0].at) > 2*time.Second {
		s = s[1:]
	}
	netRate.samples = s
	netRate.mu.Unlock()
	out := " · " + humanBytes(n) + " fetched"
	if dt := now.Sub(s[0].at).Seconds(); dt > 0.2 && n > s[0].n {
		out += " · " + humanBytes(int64(float64(n-s[0].n)/dt)) + "/s"
	}
	return out
}

// stderrProgress is newBar typed for fastboot, whose client wants a nil
// interface — not a nil pointer in one — when progress is off.
func stderrProgress() fastboot.ProgressSink {
	if b := newBar(); b != nil {
		return b
	}
	return nil
}

// spin shows a spinner labelled with the formatted text until stop is called.
// stop is idempotent and clears the line, so it can both be deferred and be
// handed to anything that is about to prompt on the terminal.
func spin(format string, a ...any) (stop func()) {
	if !stderrIsTTY {
		return func() {}
	}
	label := fmt.Sprintf(format, a...)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		frames := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			fmt.Fprintf(os.Stderr, "\r\033[K%c %s%s", frames[i%len(frames)], label, netStatus())
			select {
			case <-done:
				clearProgress()
				return
			case <-t.C:
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done); wg.Wait() }) }
}

func clearProgress() { fmt.Fprint(os.Stderr, "\r\033[K") }

// progressLine overwrites the current status line; clearProgressLine wipes it
// before the report goes to stdout.
func progressLine(format string, a ...any) {
	if !stderrIsTTY {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[K")
	fmt.Fprintf(os.Stderr, format, a...)
}

func clearProgressLine() {
	if stderrIsTTY {
		clearProgress()
	}
}
