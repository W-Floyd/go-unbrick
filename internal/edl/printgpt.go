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

// reWroteOK matches bkerler's per-partition confirmation, printed only after the
// loader ACKs the program command: "Wrote <file> to sector <N>.".
var reWroteOK = regexp.MustCompile(`(?i)Wrote .* to sector \d+`)

// ReadPartition dumps a partition by name to outfile via `edl r`, for read-back
// verification. The loader reads the whole partition, so outfile is sector-padded.
func (r *Runner) ReadPartition(ctx context.Context, workdir, loader, memory, partition, outfile string, progress io.Writer) error {
	return stream(ctx, progress, workdir, r.bin, "r", partition, outfile, "--loader="+loader, "--memory="+memory)
}

// WritePartition writes file to a partition by name via `edl w`, then inspects
// the output, because bkerler exits 0 even when a restricted loader refuses.
//
// The trustworthy signal is the "Wrote ... to sector N" line, which firehose_client
// prints only when cmd_program returns True (an ACK from the loader); a refusal
// prints "Error writing ..." or "range restricted". The old check keyed on the
// progress bar's "Sector 0x0 of 0x0", but that count is filesize//sector_size, so
// any sub-sector payload — the 44-byte CID image every setcid writes — renders as
// "of 0x0" and was misread as a rejection.
func (r *Runner) WritePartition(ctx context.Context, workdir, loader, memory, partition, file string, progress io.Writer) error {
	var buf bytes.Buffer
	w := io.MultiWriter(&buf, progress)
	if err := stream(ctx, w, workdir, r.bin, "w", partition, file, "--loader="+loader, "--memory="+memory); err != nil {
		return err
	}
	out := buf.String()
	low := strings.ToLower(out)
	if strings.Contains(low, "range restricted") || strings.Contains(low, "error writing") {
		return fmt.Errorf("loader refused the write to %s (protected region); use an "+
			"unrestricted/engineering Firehose loader or the fastboot route", partition)
	}
	if !reWroteOK.MatchString(out) {
		return fmt.Errorf("no write confirmation for %s in loader output (write not acknowledged)", partition)
	}
	return nil
}
