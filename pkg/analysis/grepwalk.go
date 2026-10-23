package analysis

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

// Searching file content by regular expression across an input (a file, package,
// image or directory, local or ssh://), through nested containers and decrypted
// members — the extract-then-strings-then-grep workflow this tool's own analysis
// sessions keep doing by hand, built in instead.

// GrepHit is one match.
type GrepHit struct {
	Path    string // from the input's root, through nested containers
	Offset  int64  // byte offset of the match within the file's (decrypted) bytes
	Line    int    // 1-based line number, 0 if the file isn't text or the line is unknown
	Context string // the matched line (text) or a short printable rendering around the match (binary)
}

// GrepOptions is what to search and how far to look.
type GrepOptions struct {
	Pattern *regexp.Regexp // required
	// Skip leaves out paths matching any of these regular expressions; see SkipPath.
	Skip []string
	// Depth is how many container levels to open. Default: unlimited.
	Depth int
	// MaxFileSize bounds how much of one file is searched. Default: 64 MiB; a
	// larger file is searched only up to this many bytes (Unreadable notes it).
	MaxFileSize int64
	// MaxMatchesPerFile stops searching one file after this many hits (0: unlimited).
	MaxMatchesPerFile int
	// OnHit is called for each hit as it is found.
	OnHit func(GrepHit)
}

// GrepResult is everything a search found.
type GrepResult struct {
	Hits       []GrepHit
	Files      int   // files searched
	Bytes      int64 // bytes actually searched
	Unreadable []string
}

const defaultGrepMaxFile = 64 << 20

// ContentMatch reports whether a leaf node's bytes contain a match for pattern,
// binary or text alike -- a plain byte-level regex match, not a printable-strings
// search, so it finds a hit sitting in otherwise-binary data too. size caps how
// much of a large file is read (0: the same default Grep uses). This is the
// primitive --grep-style content filters (tree/extract/browse/diff) build on; Grep
// itself (a flat, path-walking report of every hit) is the other consumer.
func ContentMatch(n *carve.Node, pattern *regexp.Regexp, maxSize int64) (bool, error) {
	if maxSize <= 0 {
		maxSize = defaultGrepMaxFile
	}
	data, err := n.Bytes()
	if err != nil {
		return false, err
	}
	if int64(len(data)) > maxSize {
		data = data[:maxSize]
	}
	return pattern.Match(data), nil
}

// Grep searches input's file content for opt.Pattern.
func Grep(ctx context.Context, input string, opt GrepOptions) (*GrepResult, error) {
	if opt.Pattern == nil {
		return nil, fmt.Errorf("no pattern to search for")
	}
	root, err := diffRoot(input)
	if err != nil {
		return nil, err
	}
	depth := opt.Depth
	if depth <= 0 {
		depth = 1 << 20
	}
	maxSize := opt.MaxFileSize
	if maxSize <= 0 {
		maxSize = defaultGrepMaxFile
	}
	g := &grepper{ctx: ctx, opt: opt, maxSize: maxSize, res: &GrepResult{}}
	g.walk(root, "", depth)
	if err := ctx.Err(); err != nil {
		return g.res, err
	}
	return g.res, nil
}

type grepper struct {
	ctx     context.Context
	opt     GrepOptions
	maxSize int64
	res     *GrepResult
}

func (g *grepper) walk(n *carve.Node, p string, depth int) {
	if g.ctx.Err() != nil {
		return
	}
	if n.IsDirNode() {
		_, kids, err := n.Children()
		if err != nil {
			g.res.Unreadable = append(g.res.Unreadable, p+": "+err.Error())
			return
		}
		for _, k := range kids {
			cp := p + "/" + k.Name
			if !SkipPath(g.opt.Skip, cp) {
				g.walk(k, cp, depth)
			}
		}
		return
	}
	if depth > 0 {
		if _, isContainer := carve.Format(n); isContainer {
			if _, kids, err := n.Children(); err == nil {
				for _, k := range kids {
					cp := p + "/" + k.Name
					if !SkipPath(g.opt.Skip, cp) {
						g.walk(k, cp, depth-1)
					}
				}
				return // its members are searched individually; its own bytes are redundant
			}
			// Not readable as the container it looks like: fall through and search its bytes.
		}
	}
	g.search(n, strings.TrimPrefix(p, "/"))
}

func (g *grepper) search(n *carve.Node, path string) {
	data, err := n.Bytes()
	if err != nil {
		g.res.Unreadable = append(g.res.Unreadable, path+": "+err.Error())
		return
	}
	g.res.Files++
	truncated := int64(len(data)) > g.maxSize
	if truncated {
		data = data[:g.maxSize]
	}
	g.res.Bytes += int64(len(data))
	lineStarts := textLineStarts(data) // nil if data doesn't look like text
	hits := 0
	for _, loc := range g.opt.Pattern.FindAllIndex(data, -1) {
		off := loc[0]
		h := GrepHit{Path: path, Offset: int64(off)}
		if lineStarts != nil {
			line, text := lineAt(data, lineStarts, off)
			h.Line, h.Context = line, text
		} else {
			h.Context = binaryContext(data, off, loc[1])
		}
		g.res.Hits = append(g.res.Hits, h)
		if g.opt.OnHit != nil {
			g.opt.OnHit(h)
		}
		hits++
		if g.opt.MaxMatchesPerFile > 0 && hits >= g.opt.MaxMatchesPerFile {
			break
		}
	}
	if truncated {
		g.res.Unreadable = append(g.res.Unreadable, fmt.Sprintf("%s: searched only the first %s (larger file)", path, humanSize(g.maxSize)))
	}
}

// textLineStarts returns the offset of each line's start if data looks like text
// (mostly printable, few long runs of non-text bytes), else nil. Binary-ish data
// is reported by offset instead, since "line" means nothing in it.
func textLineStarts(data []byte) []int {
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	printable, total := 0, 0
	for _, b := range sample {
		total++
		if b == '\n' || b == '\t' || b == '\r' || (b >= 0x20 && b < 0x7f) || b >= 0x80 {
			printable++
		}
	}
	if total > 0 && float64(printable)/float64(total) < 0.85 {
		return nil
	}
	starts := []int{0}
	for i, b := range data {
		if b == '\n' && i+1 < len(data) {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// lineAt is the 1-based line number and trimmed text containing offset off.
func lineAt(data []byte, lineStarts []int, off int) (int, string) {
	// lineStarts is sorted; find the last start <= off.
	lo, hi := 0, len(lineStarts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if lineStarts[mid] <= off {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	start := lineStarts[lo]
	end := len(data)
	if idx := bytes.IndexByte(data[start:], '\n'); idx >= 0 {
		end = start + idx
	}
	line := string(bytes.TrimRight(data[start:end], "\r"))
	const maxLine = 300
	if len(line) > maxLine {
		line = line[:maxLine] + "…"
	}
	return lo + 1, line
}

// binaryContext is a short printable rendering around a match in non-text data:
// non-printable bytes shown as '.', like strings(1)'s context.
func binaryContext(data []byte, start, end int) string {
	const pad = 16
	from := max(0, start-pad)
	to := min(len(data), end+pad)
	b := data[from:to]
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 0x20 && c < 0x7f {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func humanSize(n int64) string {
	const u = 1 << 20
	if n >= u {
		return fmt.Sprintf("%d MiB", n/u)
	}
	return fmt.Sprintf("%d B", n)
}
