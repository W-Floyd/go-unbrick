package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/term"

	work "github.com/W-Floyd/go-unbrick/internal/progress"
)

// showProgress prints what the long-running work in flight is doing (percent and
// time left) on one stderr line until the returned stop is called, for the wait
// before a browser has anything to show. Silent unless stderr is a terminal.
func showProgress(prefix string) (stop func()) {
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return func() {}
	}
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		t := time.NewTicker(300 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				fmt.Fprint(os.Stderr, "\r\x1b[K")
				return
			case <-t.C:
				line := prefix
				if p := work.Text(); p != "" {
					line += ": " + p
				}
				fmt.Fprint(os.Stderr, "\r\x1b[K"+line)
			}
		}
	}()
	return func() { close(done); <-exited }
}
