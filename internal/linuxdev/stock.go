package linuxdev

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"go-unbrick/internal/lp"
)

// Recovering the stock firmware's identity from a device whose booted OS is not
// the stock one. When the running system is on removable or RAM media (see
// ShellRecon.BootMedium), the original Android was never overwritten: its
// build.prop still sits in the internal system partition. That partition is a
// logical volume inside `super`; its offset comes from super's liblp metadata,
// and the device mounts it read-only there and reads build.prop out of it, so
// the kernel does the ext4 work and only a few lines cross the wire.

// stockPropKeys are the build.prop lines worth recovering — the firmware
// identity the booted OS cannot report because it is not that firmware.
var stockPropKeys = []string{
	"ro.build.fingerprint",
	"ro.system.build.fingerprint",
	"ro.build.version.security_patch",
	"ro.build.date",
}

const stockScanTimeout = time.Minute

var debugStock = os.Getenv("UNBRICK_DEBUG_STOCK") != ""

// RecoverStockProps reads the intact internal Android's build.prop when the
// booted OS is on removable/RAM media, and returns the recovered key/values. It
// is best-effort: an internal (OS-replacing) install, no super, or a mount that
// fails all return nil without error — nothing here may break a recon.
func (d *Device) RecoverStockProps() map[string]string {
	switch d.R.BootMedium() {
	case "removable", "ram":
	default:
		return nil // the stock OS was replaced, or the medium is unknown
	}
	handle := d.superHandle()
	if handle == "" {
		return nil
	}
	// Where system lives inside super, from super's own liblp metadata.
	off, size := d.systemExtent(handle)
	if debugStock {
		fmt.Printf("[stock] handle=%s system off=%d size=%d\n", handle, off, size)
	}
	if size == 0 {
		return nil
	}
	// Mount system read-only at its offset inside super and read build.prop
	// straight out of it: the kernel's ext4 driver finds the small file, so
	// nothing has to scan or parse the volume. Far faster and more reliable than
	// a raw grep, which runs at a few MiB/s on the phone and depends on where in
	// the 623 MiB the file happens to sit.
	pattern := "^(" + strings.Join(escapeProps(stockPropKeys), "|") + ")="
	script := fmt.Sprintf(`m=$(mktemp -d) || exit 0
if mount -o ro,loop,offset=%d,sizelimit=%d %s "$m" 2>/dev/null; then
	for f in build.prop system/build.prop system/system/build.prop; do
		[ -f "$m/$f" ] && grep -aE %s "$m/$f"
	done
	umount "$m" 2>/dev/null
fi
rmdir "$m" 2>/dev/null`, off, size, shellQuote(handle), shellQuote(pattern))
	out, err := d.C.Run(stockScanTimeout, d.C.elevated("sh -c "+shellQuote(script)))
	if debugStock {
		fmt.Printf("[stock] off=%d size=%d err=%v out=%q\n", off, size, err, out)
	}
	if err != nil {
		return nil
	}
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && v != "" {
			if _, want := propWanted[k]; want {
				props[k] = v
			}
		}
	}
	if len(props) == 0 {
		return nil
	}
	return props
}

var propWanted = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range stockPropKeys {
		m[k] = true
	}
	return m
}()

// superHandle is the block-device node of the super partition.
func (d *Device) superHandle() string {
	for _, p := range d.R.Partitions {
		if p.Base() == "super" && p.Handle != "" {
			return p.Handle
		}
	}
	return ""
}

// systemExtent reads super's liblp metadata off the device and returns the
// byte offset and size of the system volume within super. Zero size when the
// metadata cannot be read or holds no system partition.
func (d *Device) systemExtent(handle string) (offset, size uint64) {
	// The primary metadata sits in the first ~1 MiB; base64 so binary survives
	// the text channel.
	cmd := fmt.Sprintf("dd if=%s bs=1M count=1 2>/dev/null | base64", shellQuote(handle))
	out, err := d.C.Run(CommandTimeout, d.C.elevated("sh -c "+shellQuote(cmd)))
	if err != nil {
		return 0, 0
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(out), ""))
	if debugStock {
		fmt.Printf("[stock] meta read err=%v b64len=%d rawlen=%d isSuper=%v\n", err, len(out), len(raw), lp.IsSuper(raw))
	}
	if err != nil {
		return 0, 0
	}
	meta, err := lp.Parse(raw)
	if debugStock {
		if err != nil {
			fmt.Printf("[stock] lp.Parse err=%v\n", err)
		} else {
			var names []string
			for _, p := range meta.Partitions {
				names = append(names, fmt.Sprintf("%s@%d/%dMB", p.Name, p.OffsetBytes>>20, p.SizeBytes>>20))
			}
			fmt.Printf("[stock] super partitions: %s\n", strings.Join(names, " "))
		}
	}
	if err != nil {
		return 0, 0
	}
	// The A/B active slot's system, else any system.
	slot := d.R.Slot()
	for _, want := range []string{"system_" + slot, "system"} {
		for _, p := range meta.Partitions {
			if p.Name == want && p.OffsetBytes > 0 && p.SizeBytes > 0 {
				return p.OffsetBytes, p.SizeBytes
			}
		}
	}
	return 0, 0
}

func escapeProps(keys []string) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = strings.ReplaceAll(k, ".", `\.`)
	}
	return out
}
