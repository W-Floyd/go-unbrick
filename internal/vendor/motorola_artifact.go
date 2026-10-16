package vendor

// Content recognition for vendor file formats that have no neutral magic the
// generic filetype detector handles — Motorola's CID image, MotoLogo container
// and subsidy-lock .nvm, Samsung's .pit, Qualcomm's FSGADAPT EFS image,
// MediaTek's partition images, Download Agents and GFH files. Kept
// behind the vendor seam so the
// recon command never hardcodes vendor magics; it just asks RecognizeArtifact.

import (
	"fmt"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/lenovo"
)

// ArtifactInfo is a vendor-recognized file: a short type label and optional detail.
type ArtifactInfo struct {
	Label  string
	Detail string
}

// RecognizeArtifact identifies a vendor-specific file from its name and bytes.
// cat may be nil (used only to name a CID's carrier channel); name may be ""
// where no filename is in scope (only the name-blind checks then apply).
// Returns ok=false if no vendor format matches.
func RecognizeArtifact(cat *catalog.Catalog, name string, data []byte) (ArtifactInfo, bool) {
	// LMSA ROM (.t/.x): ciphertext has no magic, so the extension is all that
	// marks it — content-readable-as-text rules out the many non-LMSA uses of
	// the same extensions (see lenovo.IsROM).
	if lenovo.IsROM(name, data) {
		return ArtifactInfo{Label: "LMSA ROM (encrypted)"}, true
	}
	// Motorola CID image (magic 0x00F0): v0 carrier template or signed v2 record.
	if v, ok := CIDVersion(data); ok {
		info := ArtifactInfo{Label: "Motorola CID"}
		if v == 0 && len(data) >= CIDSize {
			if ch, err := CIDParse(data[:CIDSize]); err == nil {
				hexv := fmt.Sprintf("0x%04x", ch)
				info.Detail = "v0 template, channel " + hexv
				if cat != nil {
					if name := cat.CarrierIDName("motorola", hexv); name != "" {
						info.Detail += " (" + name + ")"
					} else if ref := cat.CarrierIDReference("motorola", hexv); ref != "" {
						info.Detail += " (" + ref + ")"
					}
				}
			}
		} else {
			info.Detail = fmt.Sprintf("v%d", v)
			if CIDIsSigned(data) {
				info.Detail += " signed (secure-production)"
			}
		}
		return info, true
	}
	// Motorola logo container.
	if len(data) >= 8 && string(data[:8]) == "MotoLogo" {
		return ArtifactInfo{Label: "MotoLogo container"}, true
	}
	// Subsidy-lock config (.nvm): ASCII-hex NV records beginning "8021".
	if len(data) >= 4 && string(data[:4]) == "8021" {
		if cfg, err := ParseSLCF(data); err == nil {
			d := "no lock (retail)"
			if cfg.Locked {
				d = fmt.Sprintf("LOCKED, %d-digit key, %d network(s)", cfg.ControlKeyDigits, len(cfg.PLMNs))
			}
			return ArtifactInfo{Label: "Motorola SLCF", Detail: d}, true
		}
	}
	if info, ok := fsgArtifact(data); ok {
		return info, true
	}
	if info, ok := mediatekArtifact(data); ok {
		return info, true
	}
	if p, err := ParsePIT(data); err == nil {
		return ArtifactInfo{Label: "Samsung PIT", Detail: fmt.Sprintf("%d partitions", len(p.Entries))}, true
	}
	return ArtifactInfo{}, false
}
