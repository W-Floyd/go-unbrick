package port

import (
	"fmt"
	"sort"
	"strings"
)

// Manifest lists the files of a bundle, how many decisions each leaves open
// (lines marked TODO), and the first few of them, so a person knows where to
// start. It reads the files as text; a binary file is listed with no count.
func Manifest(files map[string][]byte) string {
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("# Bundle\n")
	w("Everything here was derived from a stock package; each line that could not be settled is marked TODO, never guessed. `HARDWARE.md` has the evidence.\n")
	w("| file | size | open decisions |")
	w("|---|---|---|")
	total := 0
	type todo struct{ file, line string }
	var todos []todo
	for _, n := range names {
		text := string(files[n])
		count := 0
		for _, l := range strings.Split(text, "\n") {
			// A header that explains the convention is not itself a decision.
			if strings.Contains(l, "TODO") && !strings.Contains(l, "marked TODO") && !strings.Contains(l, "Lines marked") {
				count++
				if len(todos) < 40 && !isBinary(files[n]) {
					todos = append(todos, todo{n, strings.TrimSpace(l)})
				}
			}
		}
		if isBinary(files[n]) {
			w("| %s | %d B | — |", n, len(files[n]))
			continue
		}
		total += count
		w("| %s | %d B | %d |", n, len(files[n]), count)
	}
	w("\n%d open decisions in all.", total)
	if len(todos) > 0 {
		w("\n## First open decisions\n")
		for i, t := range todos {
			if i == 25 {
				w("- … and more; search the files for TODO")
				break
			}
			w("- `%s`: %s", t.file, trimTodo(t.line))
		}
	}
	return b.String()
}

func isBinary(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

// trimTodo cuts a long line down to its TODO, so a list reads as a list.
func trimTodo(l string) string {
	if i := strings.Index(l, "TODO"); i > 0 {
		l = l[i:]
	}
	l = strings.TrimSuffix(strings.TrimSpace(l), "*/")
	if len(l) > 140 {
		l = l[:140] + "…"
	}
	return strings.TrimSpace(l)
}
