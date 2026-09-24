package edl

import (
	"fmt"
	"strings"

	"go-unbrick/internal/secboot"
)

// Verdict is whether the PBL will authenticate a loader, judged against the
// fused values Sahara reported rather than against another image's signature.
type Verdict struct {
	Accept  bool     // no hard binding broken
	Proven  bool     // the root hash was compared, not just the ids
	Reasons []string // what broke, or what could not be checked
}

// Judge compares a loader's signing identity with the chip. The root hash is the
// binding that decides: the PBL hashes the loader's root certificate and
// compares it with OEM_PK_HASH. OEM_ID is bound too; a differing JTAG in the
// cert HW_ID is only advisory, since certs may mask it.
func Judge(chip *ChipInfo, ld *secboot.Identity) Verdict {
	v := Verdict{Accept: true}
	if !chip.Fused() {
		v.Proven = chip.PKHash != ""
		v.Reasons = append(v.Reasons, "chip reports no OEM_PK_HASH: unfused, any signature is accepted")
		return v
	}
	if o := chip.OEMID(); o != "" && ld.OEMID != "" && !strings.EqualFold(o, ld.OEMID) {
		v.Accept = false
		v.Reasons = append(v.Reasons, fmt.Sprintf("OEM_ID %s, chip is %s", strings.ToUpper(ld.OEMID), o))
	}
	root := ld.RootKeyHash(len(chip.PKHash))
	switch {
	case ld.RootSHA256 == "":
		v.Reasons = append(v.Reasons, "no root certificate in the loader to hash")
	case root == "":
		v.Reasons = append(v.Reasons, fmt.Sprintf("chip PK hash is %d hex, an unknown algorithm; not compared", len(chip.PKHash)))
	case strings.EqualFold(root, chip.PKHash):
		v.Proven = true
	default:
		v.Accept, v.Proven = false, true
		v.Reasons = append(v.Reasons, "signing root does not match the fused OEM_PK_HASH")
	}
	if j := chip.JTAGID(); j != "" && ld.JTAGID != "" && ld.JTAGID != "00000000" && !strings.EqualFold(j, ld.JTAGID) {
		v.Reasons = append(v.Reasons, fmt.Sprintf("cert HW_ID names JTAG %s, chip is %s", strings.ToUpper(ld.JTAGID), j))
	}
	return v
}
