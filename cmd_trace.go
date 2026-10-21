package main

import (
	"fmt"
	"os"
	"time"
)

// tracing is set by UNBRICK_TRACE: each phase of a long command then reports how
// long it took, on stderr, to find where the time goes.
var tracing = os.Getenv("UNBRICK_TRACE") != ""

// trace starts timing a phase; call the result when it ends.
func trace(phase string) func() {
	if !tracing {
		return func() {}
	}
	start := time.Now()
	return func() { fmt.Fprintf(os.Stderr, "[trace] %-48s %6.2fs\n", phase, time.Since(start).Seconds()) }
}
