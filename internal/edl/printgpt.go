package edl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// DevPartition is one entry read from the live device's GPT.
type DevPartition struct {
	LUN    int
	Name   string
	Offset uint64 // byte offset within the LUN
	Length uint64 // byte length
}

// DevGPT is the device partition layout read over Firehose.
type DevGPT struct {
	Parts   []DevPartition
	LunSize map[int]uint64 // LUN -> total disk size in bytes
}

// Find returns the device partition with the given name (case-insensitive).
func (g *DevGPT) Find(name string) (DevPartition, bool) {
	for _, p := range g.Parts {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return DevPartition{}, false
}

// HasLUN reports whether any partition was parsed on the given LUN.
func (g *DevGPT) HasLUN(lun int) bool {
	_, ok := g.LunSize[lun]
	return ok
}

var (
	reLun  = regexp.MustCompile(`^Parsing Lun (\d+):`)
	rePart = regexp.MustCompile(`^(\S+):\s+Offset (0x[0-9a-fA-F]+), Length (0x[0-9a-fA-F]+)`)
	reSize = regexp.MustCompile(`^Total disk size:(0x[0-9a-fA-F]+)`)
)

// ParsePrintGPT parses the text output of `edl printgpt` into a DevGPT.
func ParsePrintGPT(text string) (*DevGPT, error) {
	g := &DevGPT{LunSize: map[int]uint64{}}
	lun := -1
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if m := reLun.FindStringSubmatch(line); m != nil {
			lun, _ = strconv.Atoi(m[1])
			if _, ok := g.LunSize[lun]; !ok {
				g.LunSize[lun] = 0
			}
			continue
		}
		if m := reSize.FindStringSubmatch(line); m != nil && lun >= 0 {
			g.LunSize[lun] = parseHex(m[1])
			continue
		}
		if m := rePart.FindStringSubmatch(line); m != nil && lun >= 0 {
			g.Parts = append(g.Parts, DevPartition{
				LUN:    lun,
				Name:   m[1],
				Offset: parseHex(m[2]),
				Length: parseHex(m[3]),
			})
		}
	}
	if len(g.Parts) == 0 {
		return nil, fmt.Errorf("no partitions parsed from printgpt output (loader may have been rejected at Sahara, or wrong --memory)")
	}
	return g, nil
}

func parseHex(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	return n
}

// ReadGPT runs `edl printgpt` with the given loader and memory type, streaming
// progress, and returns the parsed device layout. workdir is the bundle dir so
// the loader filename resolves.
func (r *Runner) ReadGPT(ctx context.Context, workdir, loader, memory string, progress io.Writer) (*DevGPT, error) {
	var buf bytes.Buffer
	w := io.MultiWriter(&buf, progress)
	if err := stream(ctx, w, workdir, r.bin, "printgpt", "--loader="+loader, "--memory="+memory); err != nil {
		return nil, err
	}
	return ParsePrintGPT(buf.String())
}

// reWroteSectors matches bkerler's write summary, e.g. "Sector 0x0 of 0x0" — a
// zero total means the loader accepted the command but moved nothing.
var reWroteSectors = regexp.MustCompile(`Sector 0x[0-9a-fA-F]+ of 0x([0-9a-fA-F]+)`)

// WritePartition writes file to a partition by name via `edl w`, then inspects
// the output for the two ways a restricted loader fails while still exiting 0:
// an explicit "range restricted" error, and a zero-sector write. bkerler reports
// success in both cases, so a bare exit code is not enough to trust the write.
func (r *Runner) WritePartition(ctx context.Context, workdir, loader, memory, partition, file string, progress io.Writer) error {
	var buf bytes.Buffer
	w := io.MultiWriter(&buf, progress)
	if err := stream(ctx, w, workdir, r.bin, "w", partition, file, "--loader="+loader, "--memory="+memory); err != nil {
		return err
	}
	out := buf.String()
	if strings.Contains(strings.ToLower(out), "range restricted") {
		return fmt.Errorf("loader restricts writes to %s (protected region); the signed programmer forbids it — "+
			"use an unrestricted/engineering Firehose loader or the fastboot route", partition)
	}
	// A genuine single-sector write reports "of 0x1"; "of 0x0" means the loader
	// took the command but wrote nothing.
	for _, m := range reWroteSectors.FindAllStringSubmatch(out, -1) {
		if parseHex(m[1]) == 0 {
			return fmt.Errorf("write to %s moved 0 sectors — the loader silently rejected it (likely a protected region)", partition)
		}
	}
	return nil
}
