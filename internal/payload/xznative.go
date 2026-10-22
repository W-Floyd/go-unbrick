package payload

import (
	"bytes"
	"os/exec"
	"sync"
)

// nativeXZ finds an xz binary, "" if there is none. It decodes several times faster
// than the pure Go decoder, which a payload's xz operations spend most of a listing
// in; a variable so a test can turn it off.
var nativeXZ = sync.OnceValue(func() string {
	p, _ := exec.LookPath("xz")
	return p
})

// decodeNativeXZ decodes a plain xz stream with the xz binary; ok is false if it
// cannot, and the caller decodes it itself.
func decodeNativeXZ(data []byte) (out []byte, ok bool) {
	bin := nativeXZ()
	if bin == "" {
		return nil, false
	}
	cmd := exec.Command(bin, "-dc")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	return out, err == nil
}
