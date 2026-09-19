package vendor

// Content recognition for Motorola file formats that have no neutral magic the
// generic filetype detector handles — the CID image, the MotoLogo container, and
// the subsidy-lock .nvm. Kept behind the vendor seam so the recon command never
// hardcodes Motorola magics; it just asks RecognizeArtifact.

import (
	"fmt"

	"go-unbrick/internal/catalog"
	"go-unbrick/internal/cid"
)

// ArtifactInfo is a vendor-recognized file: a short type label and optional detail.
type ArtifactInfo struct {
	Label  string
	Detail string
}

// RecognizeArtifact identifies a vendor-specific file from its bytes. cat may be
// nil (used only to name a CID's carrier channel). Returns ok=false if no vendor
// format matches.
func RecognizeArtifact(cat *catalog.Catalog, data []byte) (ArtifactInfo, bool) {
	// Motorola CID image (magic 0x00F0): v0 carrier template or signed v2 record.
	if v, ok := cid.Version(data); ok {
		info := ArtifactInfo{Label: "Motorola CID"}
		if v == 0 && len(data) >= cid.Size {
			if ch, err := cid.Parse(data[:cid.Size]); err == nil {
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
			if cid.IsSigned(data) {
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
	return ArtifactInfo{}, false
}
