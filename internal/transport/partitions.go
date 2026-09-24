package transport

// Reading partition bytes, whatever route reached them. Which partitions are
// worth reading, in what order, and what is done with the bytes are properties
// of the *recon*, not of the route — so they live here, once, and a new reader
// (EDL, Odin) inherits them by implementing one method.

import (
	"fmt"
	"sort"
	"strings"

	"go-unbrick/internal/facts"
)

func lower(s string) string { return strings.ToLower(s) }

func stableSortBySize(p []Partition) {
	sort.SliceStable(p, func(i, j int) bool { return p[i].SizeBytes < p[j].SizeBytes })
}

// identityPartitions are the partitions worth reading during a recon, by name
// with any slot suffix removed: the ones whose *content* names the device, the
// carrier, or the trust the boot chain enforces. The bulk partitions (super,
// userdata, cache) are absent on purpose — they carry no fact a manifest does
// not state more cheaply, and one of them is the user's private data.
var identityPartitions = map[string]bool{
	// Identity and provisioning.
	"cid": true, "utags": true, "utagsbackup": true, "hw": true, "prov": true,
	// Verified boot.
	"vbmeta": true, "vbmeta_system": true, "vbmeta_vendor": true, "vbmeta_system_dlkm": true,
	// The signed boot chain: each image carries its own cert chain and build stamp.
	"abl": true, "xbl": true, "xbl_config": true, "tz": true, "hyp": true,
	"devcfg": true, "keymaster": true, "uefisecapp": true, "storsec": true,
	"qupfw": true, "aop": true, "rpm": true, "dtbo": true, "featenabler": true,
	"multiimgoem": true, "imagefv": true, "cpucp": true, "shrm": true,
	// Boot images, whose ramdisk is where an OTA key hides. Usually past the
	// default size cap; named so that raising the cap picks them up.
	"boot": true, "recovery": true, "vendor_boot": true, "init_boot": true,
}

// DefaultReadCap bounds one partition read. The signed boot chain is a few
// megabytes an image; anything larger is a filesystem or a boot image, and the
// operator asks for those explicitly by raising the cap.
const DefaultReadCap = 32 << 20

// maxConsecutiveReadFailures stops a run that is failing for a reason the next
// partition will not fix. Twenty identical permission errors tell the operator
// nothing the first one did not.
const maxConsecutiveReadFailures = 3

// IdentityPartitions selects what to read from a listed table: the
// identity-bearing partitions of the booted slot, smallest first, skipping
// anything over cap.
//
// Only the booted slot, because the running chain is the one a repair has to
// match; the inactive slot's copy is a different question (what the last update
// left behind) and costs the same again to answer.
func IdentityPartitions(parts []Partition, slot string, capBytes uint64) []Partition {
	if capBytes == 0 {
		capBytes = DefaultReadCap
	}
	var out []Partition
	for _, p := range parts {
		if !identityPartitions[lower(p.Base())] {
			continue
		}
		if s := p.Slot(); s != "" && slot != "" && s != slot {
			continue
		}
		// Size 0 is "the device would not say", not "empty": an unrooted adb
		// shell cannot read /sys/class/block at all. Such a partition is still
		// worth reading — bounded by the cap, and the reader reports a read that
		// hit the cap as truncated rather than passing a part of an image off as
		// the image.
		if p.SizeBytes > capBytes {
			continue
		}
		out = append(out, p)
	}
	// Smallest first, so a recon interrupted part way through has already
	// yielded the cheap identity partitions (cid, devcfg) rather than spent its
	// time on the largest image in the list.
	stableSortBySize(out)
	return out
}

// ReadBudget is how much a reader may transfer for a partition whose size the
// device would not report. It is the cap, so an unknown-size read is bounded by
// the same number a known-size one is checked against.
func ReadBudget(p Partition, capBytes uint64) uint64 {
	if capBytes == 0 {
		capBytes = DefaultReadCap
	}
	if p.SizeBytes == 0 || p.SizeBytes > capBytes {
		return capBytes
	}
	return p.SizeBytes
}

// Ingest reads each partition and offers it to the recognizers, which decide
// what it is from its content — the same path a file or a package member takes,
// so a partition read off a live device derives facts through exactly the rules
// a dumped image would. Each is offered as a top-level file: unlike a member of
// a package full of images, this one was asked for by name.
//
// Returns the facts set per partition and every read that failed; a partition
// that cannot be read is a finding, not a failed recon.
func Ingest(r PartitionReader, from string, b *facts.Bag, rs []facts.Recognizer, parts []Partition,
	capBytes uint64, progress func(i, n int, p Partition), save func(p Partition, data []byte) error) (map[string][]string, []error) {
	set := map[string][]string{}
	var errs []error
	failures := 0
	for i, p := range parts {
		if progress != nil {
			progress(i, len(parts), p)
		}
		data, err := r.ReadPartition(p, ReadBudget(p, capBytes))
		if err != nil {
			errs = append(errs, err)
			if failures++; failures >= maxConsecutiveReadFailures {
				if left := len(parts) - i - 1; left > 0 {
					errs = append(errs, fmt.Errorf("giving up on the remaining %d partitions after %d reads failed in a row",
						left, failures))
				}
				return set, errs
			}
			continue
		}
		failures = 0
		if save != nil {
			if err := save(p, data); err != nil {
				errs = append(errs, err)
			}
		}
		got := facts.Recognize(b, rs, facts.File{
			Name: p.Name + ".img",
			Data: data,
			From: p.Name + " (" + from + ")",
			Top:  true,
		})
		if len(got) > 0 {
			set[p.Name] = got
		}
	}
	return set, errs
}
