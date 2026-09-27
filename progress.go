package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"

	"github.com/W-Floyd/go-unbrick/internal/fastboot"
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
type barSink struct{ bar *progressbar.ProgressBar }

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
	b.bar = progressbar.NewOptions(total,
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetDescription("querying device"),
		progressbar.OptionShowDescriptionAtLineEnd(), // bar first, label after it
		progressbar.OptionSetWidth(24),
		progressbar.OptionClearOnFinish(),
	)
}

func (b *barSink) Describe(label string) {
	if b != nil && b.bar != nil {
		b.bar.Describe(label)
	}
}

func (b *barSink) Advance() {
	if b != nil && b.bar != nil {
		_ = b.bar.Add(1)
	}
}

// Clear wipes the bar mid-run, so a caller can print; the next Describe or
// Advance redraws it below whatever was printed.
func (b *barSink) Clear() {
	if b != nil && b.bar != nil {
		clearProgress()
	}
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
			fmt.Fprintf(os.Stderr, "\r\033[K%c %s", frames[i%len(frames)], label)
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
