package edl

// EDL as a recon transport: the one route into a device with no working
// software on it.
//
// It speaks in two stages. Sahara, the PBL's own protocol, answers before any
// programmer runs and reports what the fuses say — the chip id, the OEM, the
// hash of the signing root — which is identity no reflash can change. Firehose,
// the programmer the PBL then authenticates and runs, is what lists and reads
// partitions; it needs a loader signed for this chip. So without a loader this
// transport is Sahara only, and says which loader would get further.
//
// Sahara and Firehose never share a session across processes: once a loader
// runs, Sahara is gone until the device is power-cycled. A loader-backed recon
// therefore takes the chip identity from the same edlclient session that
// uploads the loader, not from a separate handshake.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/transport"
)

// Session is what one EDL recon collected: the Sahara chip identity (nil when
// the device was already in Firehose) and the booted slot as the GPT's A/B
// attributes record it.
type Session struct {
	Chip *ChipInfo
	Slot string
}

// SourceEDL is one collected EDL session.
var SourceEDL = facts.Key[*Session]("source:device.edl",
	facts.Fmt(func(s *Session) string {
		if s.Chip != nil && s.Chip.Serial != "" {
			return "edl " + s.Chip.Serial
		}
		return "edl session"
	}))

// Transport is a device in 9008 mode.
type Transport struct {
	R        *Runner
	Ctx      context.Context
	Loader   string // absolute programmer path; "" for Sahara only
	Memory   string // ufs | emmc | ""; "" lets the loader's configure decide
	Progress io.Writer

	S   Session
	GPT *DevGPT
	// firehose is whether a programmer is running, so Firehose verbs work.
	firehose bool
	// ChipCached is set when S.Chip came from a prior session's cache rather
	// than a live Sahara read this run (the loader was already up).
	ChipCached bool
	gaps       []facts.Finding
	tmp        string
}

var (
	_ transport.Transport       = (*Transport)(nil)
	_ transport.PartitionLister = (*Transport)(nil)
	_ transport.PartitionReader = (*Transport)(nil)
)

// OpenOptions selects how far a recon goes.
type OpenOptions struct {
	Loader      string // programmer to upload; "" speaks Sahara only
	Memory      string
	WaitSeconds int
	// Chip is an identity already read this power cycle (to choose Loader).
	// It stands in when the loader session's own handshake yields none.
	Chip *ChipInfo
}

// Open collects what the device will say. Without a loader only Sahara is
// spoken, unless a programmer is already running from an earlier session, in
// which case Firehose is used as found.
func Open(ctx context.Context, r *Runner, o OpenOptions, progress io.Writer) (*Transport, error) {
	loader, memory, waitSeconds := o.Loader, o.Memory, o.WaitSeconds
	t := &Transport{R: r, Ctx: ctx, Memory: memory, Progress: progress}
	if loader != "" {
		abs, err := filepath.Abs(loader)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(abs); err != nil {
			return nil, fmt.Errorf("loader: %w", err)
		}
		t.Loader = abs
	}

	if t.Loader == "" {
		chip, err := r.SaharaInfo(ctx, waitSeconds, progress)
		if err != nil {
			return nil, err
		}
		switch chip.Mode {
		case "absent":
			return nil, fmt.Errorf("no device in EDL (9008) mode within %ds", waitSeconds)
		case "sahara":
			t.S.Chip = chip
			if chip.MemoryDebug {
				t.gap("the PBL is in memory-debug (crash dump) mode, not waiting for a loader; power-cycle into EDL")
			}
			r.saveCache(&sessionCache{Chip: chip}) // Sahara-only: identity, no loader yet
			return t, nil
		case "firehose", "quiet":
			// A programmer from an earlier session is still running. Sahara is
			// gone, so the identity can only come from that session's cache;
			// the storage-serial guard below confirms it is the same device.
			if c := r.loadCache(); c != nil {
				t.S.Chip, t.ChipCached = c.Chip, true
				if t.Memory == "" {
					t.Memory = c.Memory
				}
				t.Loader = c.Loader // edlclient ignores it while a loader runs; recorded for the cache
			} else {
				t.gap("no Sahara hello on offer (a Firehose programmer is running) and no cached identity; power-cycle into EDL to read it")
			}
		default:
			return nil, fmt.Errorf("device answered in %q mode; power-cycle it back into EDL", chip.Mode)
		}
	}

	gpt, out, err := r.printGPT(ctx, t.Loader, memory, progress)
	if chip := ParseSaharaInfo(out); chip != nil && chip.HWID != "" {
		t.S.Chip, t.ChipCached = chip, false // a fresh handshake beats the cache
	} else if o.Chip != nil {
		t.S.Chip = o.Chip
	}
	if err != nil {
		// The handshake may still have yielded the chip identity: a loader the
		// PBL refused is itself a finding, not an empty recon.
		if t.S.Chip == nil {
			return nil, err
		}
		t.gap("Firehose: " + err.Error())
		return t, nil
	}
	t.GPT, t.firehose = gpt, true
	if slot, err := r.activeSlot(ctx, t.Loader, memory); err == nil {
		t.S.Slot = slot
	}

	// Validate a cached identity against the live device and refresh the cache.
	serial := r.storageSerial(ctx, t.Loader, t.Memory)
	if t.ChipCached && serial != "" {
		if c := r.loadCache(); c != nil && c.StorageSerial != "" && c.StorageSerial != serial {
			t.S.Chip, t.ChipCached = nil, false
			t.gap("cached chip identity was for a different device (storage serial mismatch); ignored")
		}
	}
	if t.S.Chip != nil {
		r.saveCache(&sessionCache{StorageSerial: serial, Chip: t.S.Chip, Loader: t.Loader, Memory: t.Memory})
	}
	return t, nil
}

func (t *Transport) gap(msg string) {
	t.gaps = append(t.gaps, facts.Finding{Severity: facts.Warn, Message: msg})
}

func (t *Transport) Name() string { return transport.EDL }

func (t *Transport) Describe() string {
	d := "edl"
	if c := t.S.Chip; c != nil {
		if c.Serial != "" {
			d += " " + c.Serial
		}
		if j := c.JTAGID(); j != "" {
			d += " (JTAG " + j + ")"
		}
	}
	return d
}

// Firehose reports whether a programmer is running.
func (t *Transport) Firehose() bool { return t.firehose }

// Close removes the read scratch dir. The programmer keeps running until the
// device is power-cycled; nothing here can stop it.
func (t *Transport) Close() error {
	if t.tmp != "" {
		return os.RemoveAll(t.tmp)
	}
	return nil
}

func (t *Transport) Sources(b *facts.Bag) []facts.Finding {
	if t.S.Chip != nil || t.S.Slot != "" {
		s := t.S
		src := "edl"
		if t.ChipCached {
			src = "edl (cached identity, same device)"
		}
		facts.Set(b, SourceEDL, &s, facts.Provenance{Source: src, Authority: facts.Attested})
	}
	return t.gaps
}

// Partitions is the live GPT across every LUN.
func (t *Transport) Partitions() []transport.Partition {
	if t.GPT == nil {
		return nil
	}
	out := make([]transport.Partition, 0, len(t.GPT.Parts))
	for _, p := range t.GPT.Parts {
		out = append(out, transport.Partition{Name: p.Name, SizeBytes: p.Length, Handle: fmt.Sprintf("lun%d", p.LUN)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (t *Transport) Slot() string { return t.S.Slot }

// ReadPartition dumps one partition over Firehose. The GPT gave every size, so
// the budget never truncates here; a partition over the cap was not selected.
func (t *Transport) ReadPartition(p transport.Partition, budget uint64) ([]byte, error) {
	if !t.firehose {
		return nil, fmt.Errorf("%s: no Firehose programmer running (pass --loader)", p.Name)
	}
	if t.tmp == "" {
		dir, err := os.MkdirTemp("", "unbrick-edl-")
		if err != nil {
			return nil, err
		}
		t.tmp = dir
	}
	out := filepath.Join(t.tmp, p.Name+".bin")
	args := append([]string{"r", p.Name, out}, t.R.sessionArgs(t.Loader, t.Memory)...)
	var log strings.Builder
	if err := stream(t.Ctx, &log, "", t.R.bin, args...); err != nil {
		return nil, fmt.Errorf("%s: %w", p.Name, err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		// edlclient exits 0 on a refused read; the missing file is the signal,
		// and the loader's own log line is the reason.
		if m := reRestricted.FindStringSubmatch(reANSI.ReplaceAllString(log.String(), "")); m != nil {
			return nil, fmt.Errorf("%s: loader refuses reads of this range (%s)", p.Name, m[1])
		}
		return nil, fmt.Errorf("%s: loader returned nothing (read refused or partition not found)", p.Name)
	}
	os.Remove(out)
	if uint64(len(data)) > budget {
		data = data[:budget]
	}
	return data, nil
}

// PrepareReads says once, before any read, that Sahara alone cannot read.
func (t *Transport) PrepareReads() error {
	if !t.firehose {
		return fmt.Errorf("no Firehose programmer running; pass --loader (or --loader=library)")
	}
	return nil
}

// ReadCost is an EDL read on the fact graph's scale: a process launch and a
// Firehose round trip per partition.
func (t *Transport) ReadCost() int { return 500 }

// sessionArgs are the flags every edlclient call of one recon shares. A loader
// is passed even once one is running: edlclient ignores it in Firehose mode.
func (r *Runner) sessionArgs(loader, memory string) []string {
	var a []string
	if loader != "" {
		a = append(a, "--loader="+loader)
	}
	if memory != "" {
		a = append(a, "--memory="+memory)
	}
	return a
}

func (r *Runner) printGPT(ctx context.Context, loader, memory string, progress io.Writer) (*DevGPT, string, error) {
	var buf strings.Builder
	args := append([]string{"printgpt"}, r.sessionArgs(loader, memory)...)
	err := stream(ctx, io.MultiWriter(&buf, progress), "", r.bin, args...)
	if err != nil {
		return nil, buf.String(), err
	}
	g, err := ParsePrintGPT(buf.String())
	return g, buf.String(), err
}

// reRestricted is a production loader's refusal of a protected range, e.g.
// "ERROR: range restricted: lun=4, start_sector=10944, num_sectors=32".
var reRestricted = regexp.MustCompile(`range restricted: ([^'"\]\n]+)`)

// reStorageSerial pulls serial_num out of the loader's getstorageinfo JSON:
// {"storage_info": {…, "serial_num":123456789, …}}.
var reStorageSerial = regexp.MustCompile(`"serial_num"\s*:\s*"?(\d+)`)

// storageSerial reads the UFS/eMMC hardware serial over Firehose, "" if the
// loader will not report it (some restricted loaders gate getstorageinfo). It
// is the device key the identity cache is validated against.
func (r *Runner) storageSerial(ctx context.Context, loader, memory string) string {
	var buf strings.Builder
	args := append([]string{"getstorageinfo"}, r.sessionArgs(loader, memory)...)
	if err := stream(ctx, &buf, "", r.bin, args...); err != nil {
		return ""
	}
	if m := reStorageSerial.FindStringSubmatch(reANSI.ReplaceAllString(buf.String(), "")); m != nil {
		return m[1]
	}
	return ""
}

var reActiveSlot = regexp.MustCompile(`Current active slot: ([ab])`)

func (r *Runner) activeSlot(ctx context.Context, loader, memory string) (string, error) {
	var buf strings.Builder
	args := append([]string{"getactiveslot"}, r.sessionArgs(loader, memory)...)
	if err := stream(ctx, &buf, "", r.bin, args...); err != nil {
		return "", err
	}
	if m := reActiveSlot.FindStringSubmatch(reANSI.ReplaceAllString(buf.String(), "")); m != nil {
		return m[1], nil
	}
	return "", fmt.Errorf("no active slot in getactiveslot output")
}

// DeviceSerial is the chip serial Sahara reported, used only to recognise the
// same physical device across a session's routes.
func (t *Transport) DeviceSerials() []string {
	var s []string
	if t.S.Chip != nil {
		s = transport.NonEmpty(t.S.Chip.Serial)
	}
	return s
}
