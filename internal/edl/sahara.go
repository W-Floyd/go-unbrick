package edl

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ChipInfo is what the PBL says about itself over Sahara before any programmer
// runs: values read from fuses, which no software on the device can change.
type ChipInfo struct {
	// Mode is where the device was found: "sahara" (PBL waiting for a loader),
	// "firehose" (a loader already running, so Sahara is gone until a power
	// cycle), "quiet" (no hello on offer, usually the same), "absent", or
	// "error".
	Mode          string
	SaharaVersion int
	MemoryDebug   bool   // the PBL is offering a crash dump, not a loader slot
	Serial        string // chip serial, 8 hex
	HWID          string // 16 hex: MSM_ID(JTAG) | OEM_ID | MODEL_ID
	PKHash        string // OEM_PK_HASH, the fused hash of the signing root
}

// JTAGID is the MSM hardware id, the loader-signing key the catalog and the
// library use ("0016F0E1").
func (c *ChipInfo) JTAGID() string {
	if len(c.HWID) != 16 {
		return ""
	}
	return strings.ToUpper(c.HWID[:8])
}

// OEMID is the OEM signing id ("02E8").
func (c *ChipInfo) OEMID() string {
	if len(c.HWID) != 16 {
		return ""
	}
	return strings.ToUpper(c.HWID[8:12])
}

// ModelID is the OEM's model id, which OEMs mostly leave zero.
func (c *ChipInfo) ModelID() string {
	if len(c.HWID) != 16 {
		return ""
	}
	return strings.ToUpper(c.HWID[12:])
}

// Fused reports whether secure boot is anchored to a real OEM root: an all-zero
// PK hash is an unfused (development) part that accepts any loader.
func (c *ChipInfo) Fused() bool {
	return strings.Trim(c.PKHash, "0") != ""
}

//go:embed sahara_info.py
var saharaHelper []byte

const saharaMarker = "GO-UNBRICK-SAHARA: "

// SaharaInfo reads the chip identity over Sahara without uploading a
// programmer, so the PBL is still waiting for one afterwards. wait bounds how
// long to look for a device in 9008 mode.
func (r *Runner) SaharaInfo(ctx context.Context, waitSeconds int, progress io.Writer) (*ChipInfo, error) {
	script := filepath.Join(r.dir, "sahara_info.py")
	if err := os.WriteFile(script, saharaHelper, 0o644); err != nil {
		return nil, fmt.Errorf("writing sahara helper: %w", err)
	}
	var buf bytes.Buffer
	py := venvBin(filepath.Join(r.dir, "venv"), "python")
	if err := stream(ctx, io.MultiWriter(&buf, progress), "", py, script, strconv.Itoa(waitSeconds)); err != nil {
		return nil, err
	}
	return parseHelperOutput(buf.String())
}

func parseHelperOutput(out string) (*ChipInfo, error) {
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, saharaMarker)
		if i < 0 {
			continue
		}
		var raw struct {
			Mode          string `json:"mode"`
			SaharaVersion int    `json:"sahara_version"`
			MemoryDebug   bool   `json:"memory_debug"`
			Serial        string `json:"serial"`
			HWID          string `json:"hwid"`
			PKHash        string `json:"pkhash"`
			Error         string `json:"error"`
		}
		if err := json.Unmarshal([]byte(line[i+len(saharaMarker):]), &raw); err != nil {
			return nil, fmt.Errorf("sahara helper output: %w", err)
		}
		if raw.Error != "" {
			return nil, fmt.Errorf("sahara: %s", raw.Error)
		}
		return &ChipInfo{Mode: raw.Mode, SaharaVersion: raw.SaharaVersion, MemoryDebug: raw.MemoryDebug,
			Serial: strings.ToLower(raw.Serial), HWID: strings.ToLower(raw.HWID), PKHash: strings.ToLower(raw.PKHash)}, nil
	}
	return nil, fmt.Errorf("sahara helper printed no result")
}

var (
	reANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	// edlclient prints the handshake in one of two shapes: the Sahara v1/v2
	// block ("HWID: 0x…", "PK_HASH: 0x…", "Serial: 0x…") or the v3 list
	// ("- HW_ID : …", "- OEM PKHASH : …", "- Chip Serial Number : …").
	reHWID    = regexp.MustCompile(`(?:HWID:\s+0x|- HW_ID : )([0-9a-fA-F]{16})`)
	rePKHash  = regexp.MustCompile(`(?:PK_HASH:\s+0x|- OEM PKHASH : )([0-9a-fA-F]{32,})`)
	reSerial  = regexp.MustCompile(`(?:^|\s)Serial:\s+0x([0-9a-fA-F]+)|- Chip Serial Number : ([0-9a-fA-F]+)`)
	reVersion = regexp.MustCompile(`Protocol version: (\d+)`)
	reMode    = regexp.MustCompile(`Mode detected: (\w+)`)
)

// ParseSaharaInfo reads the chip identity out of an edlclient session's own
// output, which prints it during the handshake before uploading the loader. It
// is how a loader-backed recon gets the identity without a second Sahara
// session. Returns nil when the output carries none (the device was already in
// Firehose).
func ParseSaharaInfo(text string) *ChipInfo {
	text = reANSI.ReplaceAllString(text, "")
	c := &ChipInfo{}
	if m := reMode.FindStringSubmatch(text); m != nil {
		c.Mode = m[1]
	}
	if m := reVersion.FindStringSubmatch(text); m != nil {
		c.SaharaVersion, _ = strconv.Atoi(m[1])
	}
	if m := reHWID.FindStringSubmatch(text); m != nil {
		c.HWID = strings.ToLower(m[1])
	}
	if m := rePKHash.FindStringSubmatch(text); m != nil {
		c.PKHash = strings.ToLower(m[1])
	}
	if m := reSerial.FindStringSubmatch(text); m != nil {
		c.Serial = strings.ToLower(m[1] + m[2])
	}
	if c.HWID == "" && c.PKHash == "" && c.Serial == "" {
		if c.Mode == "" {
			return nil
		}
		return c
	}
	if c.Mode == "" {
		c.Mode = "sahara"
	}
	return c
}
