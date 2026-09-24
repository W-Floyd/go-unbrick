package vendor

import (
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-unbrick/internal/fastboot"
)

// This file is Motorola's fastboot personality: the OEM-command structs and
// parsers (moved out of internal/fastboot, which is now vendor-neutral) plus a
// fastboot.Profile that stacks them onto the neutral Client — recon probes for
// the OEM commands, call pacing middleware, and capability qualifiers.

// ---- moved structs ----

// OEMHardwareInfo is the parsed output of `oem hw`. Despite the name, `oem hw`
// is Motorola's utags editor (the utags/utagsBackup partition), not a hardware
// query: bare or `oem hw <name>` it reads, but `oem hw <name> <value>`, `+`, `-`,
// `clear` and `lock` all WRITE. Only ever call it with no arguments — the sensor
// bits and UTags below are read from that listing.
type OEMHardwareInfo struct {
	DualSIM   bool
	ECompass  bool
	ESIM      bool
	FPS       bool // Fingerprint sensor
	NFC       bool
	RadioType string
	// UTags is every utag the SKU declares (from `.features`), each with the value
	// this unit carries and the range of values the family ships.
	UTags []UTag
}

// UTag is one Motorola utag from `oem hw`: its value on this unit, the options the
// family offers (`.range`), and, when the value is autodetected from the fused
// HW_ID rather than chosen, the rule that derives it (`.auto`).
type UTag struct {
	Name    string
	Value   string
	Range   []string // sibling configurations, e.g. ["4GB","6GB"]
	HWIDMap string   // the `.auto` derivation rule, when it keys off hwid
}

// SecurityVersions contains anti-rollback and security version indices from 'oem read_sv'.
type SecurityVersions struct {
	VbmetaRIL int
	RIL0      int
	RIL2      int
	RawLines  []string
}

// CIDProvRequest holds the output of `fastboot oem cid_prov_req`, Motorola's
// after-sales command that emits the hardware bindings its PKI server needs to
// mint a signed cid_prov_data payload. Read-only diagnostic; it exposes the SoC
// id even on a device whose cid partition is corrupt (CarrierID 0xDEAD).
//
// The real output is hex blocks. Offsets are reverse-engineered from a fogona
// unit and gated on the 0x00F0 structure marker, so a differently-shaped dump
// parses as raw only:
//
//	0x00  u16 BE format version (0x0003 = secure production)
//	0x42  16-byte per-boot nonce (see Digest) — NOT an identity
//	0x54  0x00F0 structure marker
//	0x60  4-byte SoC / JTAG id, in the clear (e.g. 001B80E1) — the persistent id
type CIDProvRequest struct {
	Supported     bool
	Raw           []byte
	FormatVersion int
	SoCID         string
	// Digest is the 16 bytes at 0x42. Despite the name it is a per-boot volatile
	// value, not a device secret: ABL computes SHA1 over an uninitialized stack
	// buffer (the seed KDF, FUN_0004e240, is an inert stub), so it changes every
	// boot and is stable only within one boot. It is not derived from any device
	// key/UID, cannot be reproduced offline, and must not be used to fingerprint a
	// unit. The persistent identity is SoCID (0x60) / the UID at 0x5c.
	Digest   string
	Fields   map[string]string
	RawLines []string
}

// PartitionDetail describes a partition entry from 'oem partition'.
type PartitionDetail struct {
	Name     string
	OffsetKB uint64
	SizeKB   uint64
	IsSuper  bool // true if dynamic partition inside 'super'
}

// PartitionDigest is one partition hash as the bootloader computed it.
type PartitionDigest struct {
	Partition string
	Algorithm string // md5 or sha256
	Digest    string // lowercase hex
	Range     string // the offset/size arguments sent, empty for a whole-partition hash
}

// Motorola's ABL carries `oem partition` subcommands its own `help` does not
// list: dump, erase, md5, sha256, moto-dump and moto-pull. `md5`/`sha256`/
// `moto-dump` hit a factory/engineering gate ("Command restricted!"); `dump`
// needs Motorola's own fastboot client ("Latest Motorola fastboot required").
// Neither gate is the OEM lock — unlocking does not lift the factory gate.
var (
	ErrOEMRestricted         = errors.New("bootloader refused the command as restricted (factory/engineering-mode gate, not the OEM lock)")
	ErrNeedsMotorolaFastboot = errors.New("command requires Motorola's own fastboot client")
)

// ---- Extras keys and typed accessors ----

const (
	keyOEMHw      = "moto:oem_hw"
	keyReadSV     = "moto:read_sv"
	keyCIDProvReq = "moto:cid_prov_req"
	keyLiveParts  = "moto:live_partitions"
	keyUnpopSlotB = "moto:unpopulated_slot_b"
	keyUnpopParts = "moto:unpopulated_parts"
	keyUnlockData = "moto:unlock_data"
)

// MotoUnlockData returns the `oem get_unlock_data` challenge wire, or "".
func MotoUnlockData(r *fastboot.DeviceRecon) string {
	v, _ := r.Get(keyUnlockData).(string)
	return v
}

// motoBinding is one device-bound field of an unlock challenge, compared
// against what getvar reported for this unit.
type motoBinding struct{ Field, Got, Want string }

// motoUnlockBinding compares the challenge's device-bound fields — the salt (the
// chip UID) and the serial — against what the rest of recon read from getvar.
// Provisioning bakes them together, so a mismatch means the cid record belongs
// to a different unit (a transplanted or cloned board): the code derived from it
// would not unlock THIS device. It is the body of both the report line and the
// registered cross-fact check, so the two cannot drift.
func motoUnlockBinding(r *fastboot.DeviceRecon, wire string) (bound []string, foreign []motoBinding) {
	rec, err := parseMotoWire(wire)
	if err != nil {
		return nil, nil
	}
	if r.UID != "" && len(rec.salt) >= 8 {
		uid := strings.ToLower(strings.ReplaceAll(r.UID, " ", ""))
		if got := hex.EncodeToString(rec.salt[:8]); got == uid {
			bound = append(bound, "UID")
		} else {
			foreign = append(foreign, motoBinding{"UID", got, uid})
		}
	}
	if r.Serial != "" && rec.serial != "" {
		if strings.EqualFold(rec.serial, r.Serial) {
			bound = append(bound, "serial")
		} else {
			foreign = append(foreign, motoBinding{"serial", rec.serial, r.Serial})
		}
	}
	return bound, foreign
}

// motoUnlockCrossCheck renders the binding verdict as a suffix for the report
// line, or "" when there is nothing to compare. Under redact it states the
// verdict without echoing the identifiers.
func motoUnlockCrossCheck(r *fastboot.DeviceRecon, wire string, redact bool) string {
	bound, foreign := motoUnlockBinding(r, wire)
	switch {
	case len(foreign) > 0:
		parts := make([]string, 0, len(foreign))
		for _, f := range foreign {
			if redact {
				parts = append(parts, f.Field)
				continue
			}
			parts = append(parts, f.Field+" "+f.Got+" ≠ "+f.Want)
		}
		return " [!] FOREIGN cid — provisioned for another device (" + strings.Join(parts, "; ") + ")"
	case len(bound) > 0:
		return " — ✓ device-bound (" + strings.Join(bound, " + ") + " match)"
	default:
		return ""
	}
}

// MotoHardware returns the parsed `oem hw` result stored on a recon, or nil.
func MotoHardware(r *fastboot.DeviceRecon) *OEMHardwareInfo {
	v, _ := r.Get(keyOEMHw).(*OEMHardwareInfo)
	return v
}

// MotoSecurityVersions returns the parsed `oem read_sv` result, or nil.
func MotoSecurityVersions(r *fastboot.DeviceRecon) *SecurityVersions {
	v, _ := r.Get(keyReadSV).(*SecurityVersions)
	return v
}

// MotoCIDProvReq returns the parsed `oem cid_prov_req` result, or nil.
func MotoCIDProvReq(r *fastboot.DeviceRecon) *CIDProvRequest {
	v, _ := r.Get(keyCIDProvReq).(*CIDProvRequest)
	return v
}

// MotoLivePartitions returns the `oem partition` table, or nil.
func MotoLivePartitions(r *fastboot.DeviceRecon) []PartitionDetail {
	v, _ := r.Get(keyLiveParts).([]PartitionDetail)
	return v
}

// MotoUnpopulated reports whether slot B was found unpopulated, and which parts.
func MotoUnpopulated(r *fastboot.DeviceRecon) (bool, []string) {
	b, _ := r.Get(keyUnpopSlotB).(bool)
	parts, _ := r.Get(keyUnpopParts).([]string)
	return b, parts
}

// ---- the profile ----

// motoFastboot is Motorola's fastboot.Profile. It carries per-recon pacing state,
// so FastbootProfile returns a fresh instance for each session.
type motoFastboot struct {
	mu   sync.Mutex
	last time.Time
}

// motoMinSpacing keeps consecutive fastboot calls apart: a tight loop of OEM
// probes can hang the bootloader, so calls are spaced ≥500ms (see the project's
// fastboot-probing note).
const motoMinSpacing = 500 * time.Millisecond

func (m *motoFastboot) Name() string { return "motorola" }

// Middleware paces calls so vendor probes never machine-gun the bootloader.
func (m *motoFastboot) Middleware() []fastboot.Middleware {
	return []fastboot.Middleware{m.pace}
}

func (m *motoFastboot) pace(next fastboot.RunFunc) fastboot.RunFunc {
	return func(timeout time.Duration, args ...string) (string, error) {
		m.mu.Lock()
		if !m.last.IsZero() {
			if d := motoMinSpacing - time.Since(m.last); d > 0 {
				time.Sleep(d)
			}
		}
		m.mu.Unlock()
		out, err := next(timeout, args...)
		m.mu.Lock()
		m.last = time.Now()
		m.mu.Unlock()
		return out, err
	}
}

// EDLNote flags that Motorola's `oem blankflash` route is behind a factory gate
// the OEM lock does not lift (identical on locked and unlocked fogona units).
func (m *motoFastboot) EDLNote() string {
	return "oem blankflash is factory-gated; unlocking will not lift it"
}

// Support qualifies operations against known Motorola quirks.
func (m *motoFastboot) Support(op fastboot.Op) fastboot.Support {
	switch op {
	case fastboot.OpWriteCID:
		// The lite loader ACKs a cid write and discards it (docs/motorola §3.4).
		return fastboot.Broken
	default:
		return fastboot.Native
	}
}

// PlanReconSteps reads the partition table before the probes run and returns the
// number of unpopulated partitions the `oem partition` probe will then confirm —
// so those paced round trips are in the progress-bar total from the start rather
// than growing it mid-run. The table it reads is cached on r for the probe.
func (m *motoFastboot) PlanReconSteps(c *fastboot.Client, serial string, r *fastboot.DeviceRecon) int {
	return len(m.readPartitionTable(c, serial, r))
}

// readPartitionTable returns the unpopulated-partition list from `oem partition`,
// reading and caching the table on r the first time and reusing the cache after
// (PlanReconSteps reads it; the probe reuses it — one round trip, not two).
func (m *motoFastboot) readPartitionTable(c *fastboot.Client, serial string, r *fastboot.DeviceRecon) []string {
	if list, ok := r.Get(keyUnpopParts).([]string); ok {
		return list
	}
	out, err := c.Exec(serial, 3*time.Second, "oem", "partition")
	if err != nil {
		return nil
	}
	parts, unpop, unpopList := ParseOEMPartitionOutput(out)
	r.Set(keyLiveParts, parts)
	r.Set(keyUnpopSlotB, unpop)
	r.Set(keyUnpopParts, unpopList)
	return unpopList
}

// ReconProbes are Motorola's OEM queries run after the neutral `getvar all`.
func (m *motoFastboot) ReconProbes() []fastboot.ReconProbe {
	return []fastboot.ReconProbe{
		{Name: "oem hw", Run: func(c *fastboot.Client, serial string, r *fastboot.DeviceRecon) {
			if out, err := c.Exec(serial, 2*time.Second, "oem", "hw"); err == nil {
				if hw := ParseOEMHwOutput(out); hw != nil {
					r.Set(keyOEMHw, hw)
				}
			}
		}},
		{Name: "oem read_sv", Run: func(c *fastboot.Client, serial string, r *fastboot.DeviceRecon) {
			if out, err := c.Exec(serial, 2*time.Second, "oem", "read_sv"); err == nil {
				if sv := ParseOEMReadSVOutput(out); sv != nil {
					r.Set(keyReadSV, sv)
				}
			}
		}},
		{Name: "oem cid_prov_req", Run: func(c *fastboot.Client, serial string, r *fastboot.DeviceRecon) {
			if out, err := c.Exec(serial, 3*time.Second, "oem", "cid_prov_req"); err == nil {
				if cp := ParseOEMCIDProvReqOutput(out); cp.Supported {
					r.Set(keyCIDProvReq, cp)
				}
			}
		}},
		{Name: "oem get_unlock_data", Run: func(c *fastboot.Client, serial string, r *fastboot.DeviceRecon) {
			// Read-only challenge export (no state change, no allowance consumed).
			// Store only a well-formed 4-field wire; anything else is a device that
			// does not answer it. Masked under --redact by the reporter (secret).
			if wire, err := m.GetUnlockData(c, serial); err == nil && strings.Count(wire, "#") == 3 {
				r.Set(keyUnlockData, wire)
			}
		}},
		{Name: "oem partition", Run: func(c *fastboot.Client, serial string, r *fastboot.DeviceRecon) {
			// The table read happened in PlanReconSteps (so the confirm count is in
			// the bar total up front); reuse it. Cross-check only the partitions we
			// report unpopulated, and only for size + logical flag — the two facts
			// the verdict rests on.
			unpopList := m.readPartitionTable(c, serial, r)
			if len(unpopList) > 0 {
				r.PartitionFacts = c.ProbePartitionState(serial, unpopList)
			}
		}},
	}
}

// ---- capability methods (asserted from cmd via the interfaces below) ----

// GetUnlockData queries Motorola's OEM unlock-data token (the get_unlock_data
// wire string the unlock verifier consumes).
func (m *motoFastboot) GetUnlockData(c *fastboot.Client, serial string) (string, error) {
	out, err := c.Exec(serial, 5*time.Second, "oem", "get_unlock_data")
	if err != nil && !strings.Contains(out, "(bootloader)") {
		return "", err
	}
	var tokenParts []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "(bootloader)"))
		if len(trimmed) > 16 && !strings.Contains(trimmed, " ") {
			tokenParts = append(tokenParts, trimmed)
		}
	}
	if len(tokenParts) == 0 {
		return strings.TrimSpace(out), nil
	}
	return strings.Join(tokenParts, ""), nil
}

// OEMPartitionHash asks the bootloader to hash a partition in place ('oem
// partition md5|sha256'). offset/size pass through verbatim when non-empty.
func (m *motoFastboot) OEMPartitionHash(c *fastboot.Client, serial, algo, partition, offset, size string) (*PartitionDigest, error) {
	args := []string{"oem", "partition", algo, partition}
	if offset != "" {
		args = append(args, offset)
		if size != "" {
			args = append(args, size)
		}
	}
	out, runErr := c.Exec(serial, 30*time.Second, args...)
	digest, err := ParseOEMPartitionHashOutput(out, algo)
	if err != nil {
		return nil, err
	}
	if digest == "" {
		if runErr != nil {
			return nil, runErr
		}
		return nil, errors.New("no " + algo + " digest in bootloader output: " + strings.TrimSpace(out))
	}
	d := &PartitionDigest{Partition: partition, Algorithm: algo, Digest: digest}
	if offset != "" {
		d.Range = offset
		if size != "" {
			d.Range += "+" + size
		}
	}
	return d, nil
}

// OEMPartitions queries live partition geometry ('oem partition').
func (m *motoFastboot) OEMPartitions(c *fastboot.Client, serial string) ([]PartitionDetail, bool, []string, error) {
	out, err := c.Exec(serial, 5*time.Second, "oem", "partition")
	if err != nil {
		return nil, false, nil, err
	}
	parts, unpop, unpopList := ParseOEMPartitionOutput(out)
	return parts, unpop, unpopList, nil
}

// FastbootProfile implements FastbootProfiler for the Motorola driver.
func (motorola) FastbootProfile() fastboot.Profile { return &motoFastboot{} }

// ReconReport renders Motorola's recon sections (sensors, anti-rollback, CID
// provisioning request, utag variant space) from the recon Extras.
func (m *motoFastboot) ReconReport(r *fastboot.DeviceRecon, redact bool) []fastboot.ReportSection {
	var lines []fastboot.ReportLine

	if hw := MotoHardware(r); hw != nil {
		var feats []string
		if hw.FPS {
			feats = append(feats, "Fingerprint (FPS)")
		}
		if hw.ECompass {
			feats = append(feats, "E-Compass")
		}
		if hw.NFC {
			feats = append(feats, "NFC")
		}
		if hw.ESIM {
			feats = append(feats, "eSIM")
		}
		if hw.DualSIM {
			feats = append(feats, "Dual-SIM")
		}
		featStr := strings.Join(feats, ", ")
		if featStr == "" {
			featStr = "None detected"
		}
		lines = append(lines, fastboot.ReportLine{Label: "Features / Sensors", Value: featStr})
	}

	if sv := MotoSecurityVersions(r); sv != nil && (sv.RIL0 > 0 || sv.RIL2 > 0) {
		lines = append(lines, fastboot.ReportLine{
			Label: "Anti-Rollback (RIL)",
			Value: strconv.Itoa(sv.RIL0) + " (#0), " + strconv.Itoa(sv.RIL2) + " (#2, active)",
		})
	}

	if cp := MotoCIDProvReq(r); cp != nil {
		var parts []string
		if cp.SoCID != "" {
			soc := cp.SoCID
			if r.JTAGID != "" && strings.EqualFold(cp.SoCID, r.JTAGID) {
				soc += " (= JTAG_ID)"
			}
			parts = append(parts, "SoC "+soc)
		}
		if cp.FormatVersion != 0 {
			parts = append(parts, "fmt v"+strconv.Itoa(cp.FormatVersion))
		}
		if cp.Digest != "" {
			// Per-boot nonce, not an id — flag it so it is not mistaken for one.
			parts = append(parts, "nonce "+fastboot.Mask(redact, cp.Digest)+" (per-boot, volatile)")
		}
		kv := make([]string, 0, len(cp.Fields))
		for k, v := range cp.Fields {
			kv = append(kv, k+"="+v)
		}
		sort.Strings(kv)
		parts = append(parts, kv...)
		if len(parts) == 0 {
			parts = append(parts, "available ("+strconv.Itoa(len(cp.RawLines))+" line(s), pass --raw for the dump)")
		}
		lines = append(lines, fastboot.ReportLine{Label: "CID Prov Req (moto)", Value: strings.Join(parts, ", ")})
	}

	if wire := MotoUnlockData(r); wire != "" {
		// The bootloader-unlock challenge (id#serial+model#target#salt) fed to
		// Motorola's unlock portal. Per-device secret → masked under --redact.
		v := fastboot.Mask(redact, wire)
		if r.Unlocked {
			v += " (already unlocked — informational)"
		}
		v += motoUnlockCrossCheck(r, wire, redact)
		lines = append(lines, fastboot.ReportLine{Label: "Unlock Challenge", Value: v})
	}

	var secs []fastboot.ReportSection
	if len(lines) > 0 {
		secs = append(secs, fastboot.ReportSection{Title: "Motorola OEM", Lines: lines})
	}

	// Hardware variant space, from the device's own utags — only utags with more
	// than one option, or a fused hwid derivation, say anything about the family.
	if hw := MotoHardware(r); hw != nil {
		var utagLines []fastboot.ReportLine
		for _, u := range hw.UTags {
			if len(u.Range) <= 1 && u.HWIDMap == "" {
				continue
			}
			val := u.Value
			if val == "" {
				val = "(unset)"
			}
			desc := val
			if len(u.Range) > 1 {
				desc = val + "  of {" + strings.Join(u.Range, ", ") + "}"
			}
			if u.HWIDMap != "" {
				desc += "  [" + u.HWIDMap + "]"
			}
			utagLines = append(utagLines, fastboot.ReportLine{Label: u.Name, Value: desc})
		}
		if len(utagLines) > 0 {
			secs = append(secs, fastboot.ReportSection{Title: "Hardware Variants (utags)", Lines: utagLines})
		}
	}

	// Slot B root cause: dynamic partitions unpopulated in 'super'.
	if unpop, unpopParts := MotoUnpopulated(r); unpop {
		notes := []string{
			"Dynamic partitions in 'super' are unpopulated (0 KB): " + strings.Join(unpopParts, ", "),
			"Slot B has no installed Android OS system image; it is expected to be unbootable.",
		}
		if confirm := motoConfirmUnpopulated(r, unpopParts); confirm != "" {
			notes = append(notes, confirm)
		}
		secs = append(secs, fastboot.ReportSection{Title: "Slot B Root Cause", Notes: notes})
	}
	return secs
}

// motoConfirmUnpopulated cross-checks the empty-slot-B verdict (read off one text
// dump) against the bootloader's per-partition answers. A disagreement matters
// more than the confirmation: it would mean the parts are populated and something
// else is keeping slot B down.
func motoConfirmUnpopulated(r *fastboot.DeviceRecon, unpopParts []string) string {
	if len(r.PartitionFacts) == 0 || len(unpopParts) == 0 {
		return ""
	}
	var disagree []string
	checked := 0
	for _, name := range unpopParts {
		f, ok := r.PartitionFacts[name]
		if !ok {
			continue
		}
		checked++
		if f.SizeBytes > 0 || !f.IsLogical {
			disagree = append(disagree, name)
		}
	}
	switch {
	case checked == 0:
		return ""
	case len(disagree) > 0:
		return "[!] but the device reports these as present: " + strings.Join(disagree, ", ") + " — the emptiness is not confirmed"
	default:
		return "Confirmed against the device: all " + strconv.Itoa(checked) + " report is-logical=yes, partition-size=0."
	}
}

// RawReport renders the vendor part of the --raw dump: the cid_prov_req bytes and
// the read_sv lines.
func (m *motoFastboot) RawReport(r *fastboot.DeviceRecon, redact bool) []fastboot.ReportSection {
	var secs []fastboot.ReportSection

	if cp := MotoCIDProvReq(r); cp != nil {
		notes := []string{"oem cid_prov_req (" + strconv.Itoa(len(cp.Raw)) + " bytes):"}
		if len(cp.Raw) > 0 {
			dump := cp.Raw
			if redact {
				// Blank the sensitive regions: the persistent chip serial (0x5C) and,
				// for tidiness, the per-boot nonce (0x42) — the latter is volatile, not
				// an identity, but there is no reason to share it either.
				dump = append([]byte(nil), cp.Raw...)
				for _, rg := range [][2]int{{0x42, 0x52}, {0x5c, 0x60}} {
					for i := rg[0]; i < rg[1] && i < len(dump); i++ {
						dump[i] = 0
					}
				}
			}
			for off := 0; off < len(dump); off += 16 {
				end := off + 16
				if end > len(dump) {
					end = len(dump)
				}
				row := dump[off:end]
				var asc strings.Builder
				for _, b := range row {
					if b >= 32 && b < 127 {
						asc.WriteByte(b)
					} else {
						asc.WriteByte('.')
					}
				}
				notes = append(notes, "  "+pad4(off)+": "+hexSpacedMoto(row)+"  "+asc.String())
			}
		} else {
			for _, l := range cp.RawLines {
				notes = append(notes, "  "+l)
			}
		}
		secs = append(secs, fastboot.ReportSection{Notes: notes})
	}

	if sv := MotoSecurityVersions(r); sv != nil && len(sv.RawLines) > 0 {
		notes := []string{"oem read_sv:"}
		for _, l := range sv.RawLines {
			notes = append(notes, "  "+l)
		}
		secs = append(secs, fastboot.ReportSection{Notes: notes})
	}
	return secs
}

func pad4(n int) string {
	s := strconv.FormatInt(int64(n), 16)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

func hexSpacedMoto(b []byte) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		h := strconv.FormatInt(int64(x), 16)
		if len(h) < 2 {
			h = "0" + h
		}
		sb.WriteString(h)
	}
	return sb.String()
}

// ---- moved parsers ----

// reHexLine matches a bootloader line that is nothing but hex.
var reHexLine = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// ParseOEMCIDProvReqOutput parses an `oem cid_prov_req` dump: a run of hex blocks
// concatenated and decoded per CIDProvRequest's offsets, or "key: value" lines
// into Fields. Supported is false when the bootloader rejects the command.
func ParseOEMCIDProvReqOutput(text string) *CIDProvRequest {
	r := &CIDProvRequest{Fields: map[string]string{}}
	var hexParts []string
	for _, line := range strings.Split(text, "\n") {
		hadPrefix := strings.Contains(line, "(bootloader)")
		l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "(bootloader)"))
		if l == "" {
			continue
		}
		low := strings.ToLower(l)
		if !hadPrefix && (strings.HasPrefix(low, "okay") || strings.HasPrefix(low, "finished") ||
			strings.HasPrefix(low, "failed")) {
			continue
		}
		if strings.Contains(low, "unknown command") || strings.Contains(low, "not a supported") ||
			strings.Contains(low, "not supported") {
			continue
		}
		r.Supported = true
		r.RawLines = append(r.RawLines, l)
		if reHexLine.MatchString(l) && len(l)%2 == 0 {
			hexParts = append(hexParts, l)
		} else if k, v, ok := strings.Cut(l, ":"); ok {
			if k, v = strings.TrimSpace(k), strings.TrimSpace(v); k != "" && v != "" {
				r.Fields[k] = v
			}
		}
	}
	if b, err := hex.DecodeString(strings.Join(hexParts, "")); err == nil && len(b) > 0 {
		r.Raw = b
		decodeCIDProvStruct(r)
	}
	return r
}

// decodeCIDProvStruct extracts labelled fields from the payload, gated on the
// 0x00F0 marker so a differently-shaped dump stays raw-only.
func decodeCIDProvStruct(r *CIDProvRequest) {
	b := r.Raw
	if len(b) >= 0x02 {
		r.FormatVersion = int(b[0])<<8 | int(b[1])
	}
	if len(b) >= 0x56 && b[0x54] == 0x00 && b[0x55] == 0xf0 {
		if len(b) >= 0x64 {
			r.SoCID = strings.ToUpper(hex.EncodeToString(b[0x60:0x64]))
		}
		if len(b) >= 0x52 {
			r.Digest = hex.EncodeToString(b[0x42:0x52])
		}
	}
}

// ParseOEMPartitionHashOutput pulls the digest out of an `oem partition
// md5|sha256` reply, or reports which gate refused it.
func ParseOEMPartitionHashOutput(text, algo string) (string, error) {
	want := 64
	if strings.EqualFold(algo, "md5") {
		want = 32
	}
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "(bootloader)"))
		switch {
		case strings.Contains(l, "Command restricted"):
			return "", ErrOEMRestricted
		case strings.Contains(l, "Latest Motorola fastboot required"):
			return "", ErrNeedsMotorolaFastboot
		}
		for _, tok := range strings.FieldsFunc(l, func(r rune) bool { return r == ' ' || r == ':' || r == '\t' || r == '=' }) {
			tok = strings.ToLower(strings.TrimSpace(tok))
			if len(tok) == want && strings.Trim(tok, "0123456789abcdef") == "" {
				return tok, nil
			}
		}
	}
	return "", nil
}

// ParseOEMHwOutput parses the output of 'fastboot oem hw'. Beyond the sensor
// booleans it captures each feature's value, the range the family ships, and the
// hwid-derivation rule when the value is fused rather than chosen.
func ParseOEMHwOutput(text string) *OEMHardwareInfo {
	hw := &OEMHardwareInfo{}
	feats := map[string]*UTag{}
	var order []string
	hasAny := false

	get := func(name string) *UTag {
		f, ok := feats[name]
		if !ok {
			f = &UTag{Name: name}
			feats[name] = f
		}
		return f
	}

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "(bootloader)"))
		if trimmed == "" || strings.HasPrefix(trimmed, "OKAY") || strings.HasPrefix(trimmed, "Finished") {
			continue
		}
		if strings.HasPrefix(trimmed, ",") {
			order = append(order, splitCSV(trimmed)...)
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		keyLower := strings.ToLower(key)

		switch {
		case keyLower == ".features":
			order = append(order, splitCSV(val)...)
			continue
		case strings.HasPrefix(keyLower, ".") || keyLower == "":
			continue
		}

		name, attr, hasAttr := strings.Cut(keyLower, "/")
		switch {
		case !hasAttr:
			get(name).Value = val
			hasAny = true
		case attr == ".range":
			get(name).Range = splitCSV(val)
		case attr == ".auto" && strings.Contains(val, "hwid"):
			get(name).HWIDMap = val
		}
	}

	if !hasAny {
		return nil
	}

	valOf := func(n string) string {
		if f, ok := feats[n]; ok {
			return f.Value
		}
		return ""
	}
	hw.DualSIM = strings.EqualFold(valOf("dualsim"), "true")
	hw.ECompass = strings.EqualFold(valOf("ecompass"), "true")
	hw.ESIM = strings.EqualFold(valOf("esim"), "true")
	hw.FPS = strings.EqualFold(valOf("fps"), "true")
	hw.NFC = strings.EqualFold(valOf("nfc"), "true")
	hw.RadioType = valOf("radio")

	seen := map[string]bool{}
	for _, n := range order {
		if f, ok := feats[n]; ok && !seen[n] {
			hw.UTags = append(hw.UTags, *f)
			seen[n] = true
		}
	}
	for _, n := range sortedKeysHW(feats) {
		if !seen[n] {
			hw.UTags = append(hw.UTags, *feats[n])
		}
	}
	return hw
}

// splitCSV splits a comma list, trimming blanks.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sortedKeysHW(m map[string]*UTag) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParseOEMReadSVOutput parses the security versions / anti-rollback registers.
func ParseOEMReadSVOutput(text string) *SecurityVersions {
	sv := &SecurityVersions{}
	hasAny := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "(bootloader)"))
		if trimmed == "" || strings.HasPrefix(trimmed, "OKAY") || strings.HasPrefix(trimmed, "Finished") {
			continue
		}
		sv.RawLines = append(sv.RawLines, trimmed)
		if strings.Contains(trimmed, "RIL #0 =") {
			if parts := strings.Split(trimmed, "="); len(parts) == 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					sv.RIL0 = n
					hasAny = true
				}
			}
		} else if strings.Contains(trimmed, "RIL #2 =") {
			if parts := strings.Split(trimmed, "="); len(parts) == 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					sv.RIL2 = n
					hasAny = true
				}
			}
		} else if strings.Contains(trimmed, "vbmeta RIL is") {
			parts := strings.Fields(trimmed)
			if len(parts) > 0 {
				lastToken := strings.TrimSuffix(parts[len(parts)-1], ".")
				if n, err := strconv.Atoi(lastToken); err == nil {
					sv.VbmetaRIL = n
					hasAny = true
				}
			}
		}
	}
	if !hasAny && len(sv.RawLines) == 0 {
		return nil
	}
	return sv
}

// ParseOEMPartitionOutput parses the partition table and dynamic super layout.
func ParseOEMPartitionOutput(text string) ([]PartitionDetail, bool, []string) {
	var partitions []PartitionDetail
	var unpopulated []string
	var superOffset uint64
	hasSuper := false

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "(bootloader)"))
		if trimmed == "" || strings.HasPrefix(trimmed, "OKAY") || strings.HasPrefix(trimmed, "Finished") {
			continue
		}
		idxColon := strings.Index(trimmed, ":")
		if idxColon == -1 {
			continue
		}
		name := strings.TrimSpace(trimmed[:idxColon])
		rest := trimmed[idxColon+1:]

		var offsetKB, sizeKB uint64
		for _, token := range strings.Split(rest, ",") {
			token = strings.TrimSpace(token)
			if strings.HasPrefix(token, "offset=") {
				valStr := strings.TrimSuffix(strings.TrimPrefix(token, "offset="), "KB")
				offsetKB, _ = strconv.ParseUint(valStr, 10, 64)
			} else if strings.HasPrefix(token, "size=") {
				valStr := strings.TrimSuffix(strings.TrimPrefix(token, "size="), "KB")
				sizeKB, _ = strconv.ParseUint(valStr, 10, 64)
			}
		}

		if name == "super" {
			superOffset = offsetKB
			hasSuper = true
		}
		isDynamic := hasSuper && offsetKB == superOffset && name != "super"
		partitions = append(partitions, PartitionDetail{Name: name, OffsetKB: offsetKB, SizeKB: sizeKB, IsSuper: isDynamic})
		if isDynamic && strings.HasSuffix(name, "_b") && sizeKB == 0 {
			unpopulated = append(unpopulated, name)
		}
	}
	return partitions, len(unpopulated) > 0, unpopulated
}
