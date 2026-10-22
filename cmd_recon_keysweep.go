package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/term"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// --exhaustive-key-learn: analysis.SweepKeys with the loaded secrets, drawn for a
// terminal: hits as they are found, one transient status line for the file in progress.

// knownKeyFile is where a key and IV are already known to live: files by these names.
func knownKeyFile(path string) bool {
	switch path[strings.LastIndexByte(path, '/')+1:] {
	case "iv.dat", "image.dat":
		return true
	}
	return false
}

// sweepScreen writes lines above a status line that is redrawn in place.
type sweepScreen struct {
	mu     sync.Mutex
	status bool // a status line is on screen
}

// say prints to w, wiping the status line first.
func (s *sweepScreen) say(w io.Writer, format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wipe()
	fmt.Fprintf(w, format, args...)
}

func (s *sweepScreen) wipe() {
	if s.status {
		fmt.Fprint(os.Stderr, "\r\033[K")
		s.status = false
	}
}

// draw shows the file in progress as a bar, with the totals so far.
func (s *sweepScreen) draw(p analysis.KeySweepProgress) {
	if !stderrIsTTY {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	width, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || width < 40 {
		width = 100
	}
	var bar string
	if p.Size > 0 {
		done := min(p.Done, p.Size)
		const cells = 20
		fill := int(done * cells / p.Size)
		bar = fmt.Sprintf("[%s%s] %3d%% %s/%s  ", strings.Repeat("█", fill), strings.Repeat("░", cells-fill),
			100*done/p.Size, humanBytes(done), humanBytes(p.Size))
	}
	tail := fmt.Sprintf("  · %s, %d files", humanBytes(p.TotalBytes), p.Files)
	room := max(width-1-len([]rune(bar))-len([]rune(tail)), 10)
	path := []rune(p.Path)
	if len(path) > room {
		path = append([]rune("…"), path[len(path)-room+1:]...)
	}
	fmt.Fprintf(os.Stderr, "\r\033[K%s%s%s", bar, string(path), tail)
	s.status = true
}

// runKeySweep searches input for every loaded secret.
func runKeySweep(input string, depth int) error {
	if secretsLoaded() == 0 {
		return fmt.Errorf("--exhaustive-key-learn: no keys or IVs loaded (--secrets)")
	}
	// carveRoot sets up the container formats and secrets the sweep opens through.
	if _, err := carveRoot(input); err != nil {
		return err
	}
	var scr sweepScreen
	hits := map[string][]string{}
	newHits := 0
	res, err := analysis.SweepKeys(context.Background(), input, analysis.KeySweepOptions{
		Depth: depth,
		Skip: func(name string) bool {
			return nameSkipped(reconSkip, name)
		},
		Known: knownKeyFile,
		OnHit: func(h analysis.KeyHit) {
			tag := "known"
			if !h.Known {
				tag = render(styleGood.Bold(true), "NEW")
				newHits++
			}
			loc := fmt.Sprintf("%-5s %s @%d (%s)", tag, h.Path, h.Offset, h.Encoding)
			hits[h.Name] = append(hits[h.Name], loc)
			scr.say(os.Stdout, "%s  %s\n", loc, h.Name)
		},
		OnProgress: scr.draw,
	})
	scr.mu.Lock()
	scr.wipe()
	scr.mu.Unlock()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "note: searched for %d value(s) as raw bytes and hex text\n", res.Searched)
	reportKeySweep(res, hits, newHits)
	return nil
}

func reportKeySweep(res *analysis.KeySweepResult, hits map[string][]string, newHits int) {
	fmt.Printf("\n%s searched in %d files\n", humanBytes(res.Bytes), res.Files)
	if n := len(res.Unreadable); n > 0 {
		// Each was searched as the bytes of what holds it, where there was one.
		fmt.Printf("%d could not be read as listed:\n", n)
		for _, u := range res.Unreadable[:min(n, 10)] {
			fmt.Printf("  %s\n", u)
		}
		if n > 10 {
			fmt.Printf("  … and %d more\n", n-10)
		}
	}
	if len(hits) == 0 {
		fmt.Println("no key or IV found anywhere")
		return
	}
	names := make([]string, 0, len(hits))
	for n := range hits {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("%s: %d place(s)\n", n, len(hits[n]))
	}
	if newHits == 0 {
		fmt.Println("nothing outside the known iv.dat / image.dat files")
	} else {
		fmt.Printf("%d place(s) beyond the known iv.dat / image.dat files\n", newHits)
	}
}
