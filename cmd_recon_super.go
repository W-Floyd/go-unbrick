package main

import (
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/Xe/erofs"

	"go-unbrick/internal/facts"
	"go-unbrick/internal/lp"
	"go-unbrick/internal/payload"
	"go-unbrick/internal/sparse"
	"go-unbrick/internal/srcfile"
)

// padReaderAt presents a byte slice as an io.ReaderAt that zero-fills any read
// past the end instead of returning a short read/EOF.
type padReaderAt struct{ b []byte }

func (p padReaderAt) ReadAt(dst []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("padReaderAt: negative offset %d", off)
	}
	var n int
	if off < int64(len(p.b)) {
		n = copy(dst, p.b[off:])
	}
	for i := n; i < len(dst); i++ {
		dst[i] = 0
	}
	return len(dst), nil
}

// learnSystemProps reads the package's system partition build.prop and folds its
// firmware-identity facts into the bag, exactly as on-device recovery does from
// the mounted /system (same keys, same Attested authority) — so a package and a
// unit report the identical ro.system.build.fingerprint. Best-effort and silent:
// a package with no super, or an unreadable one, simply adds nothing.
func learnSystemProps(path string, bag *facts.Bag) {
	stop := spin("reading system build.prop…")
	// Two package shapes carry the system partition: a Motorola-style flashable
	// zip has it as a liblp volume in super.img sparsechunks; an AOSP OTA has it
	// inside payload.bin. Both are generic Android containers, so both are read
	// here; whichever the package is, the props map to the same facts.
	source := "super system/build.prop"
	props := systemBuildProps(path)
	if props == nil {
		props = payloadSystemProps(path)
		source = "payload system/build.prop"
	}
	stop()
	for key, val := range props {
		if f, ok := stockPropToFact[key]; ok {
			facts.Set(bag, f, val, facts.Provenance{Source: source, Authority: facts.Attested})
		}
	}
}

// payloadSystemProps reads the system partition's build.prop out of an AOSP OTA
// package's payload.bin. Best-effort: a package with no payload, or one whose
// system is not readable, returns nil.
func payloadSystemProps(path string) map[string]string {
	dbg := v.GetBool("debug-stock")
	p, closer, err := payload.OpenZip(path)
	if err != nil {
		if dbg {
			fmt.Printf("[payload] open: %v\n", err)
		}
		return nil
	}
	defer closer.Close()
	name := payloadSystemPartition(p)
	if name == "" {
		return nil
	}
	// A lazy ReaderAt over the partition, so the EROFS reader decompresses only
	// the operations covering build.prop and the metadata it walks to reach it —
	// not the whole multi-GB system image.
	ra, _, err := p.PartitionReaderAt(name)
	if err != nil {
		if dbg {
			fmt.Printf("[payload] reader %s: %v\n", name, err)
		}
		return nil
	}
	return propsFromSystemImageAt(ra)
}

// payloadSystemPartition picks the system partition to read: the active-slot or
// slotless system image the OTA writes.
func payloadSystemPartition(p *payload.Payload) string {
	names := p.Partitions()
	for _, want := range []string{"system", "system_a"} {
		for _, n := range names {
			if n == want {
				return n
			}
		}
	}
	return ""
}

// systemStockPropKeys are the build.prop lines worth reading from a package's
// system partition — the same set the on-device recovery reads (see
// linuxdev.stockPropKeys), so the two vantages report the identical facts.
var systemStockPropKeys = map[string]bool{
	"ro.build.fingerprint":            true,
	"ro.system.build.fingerprint":     true,
	"ro.build.version.security_patch": true,
	"ro.build.date":                   true,
}

// systemBuildProps reads the stock build.prop of the system logical volume
// inside a package's super image, returning the wanted key/values. This is the
// same file the device mounts out of super, so ro.system.build.fingerprint here
// is the true Motorola System Image identity (device=msi) rather than the boot
// ramdisk's stale prop.default snapshot. Best-effort: any failure returns nil —
// reading it must never break a recon.
//
// Super is multi-GiB, so it is never fully expanded: liblp (at the front of the
// first chunk) gives system's byte extent, and only the chunks overlapping that
// extent are decoded, copying just the system volume out.
func systemBuildProps(path string) map[string]string {
	dbg := v.GetBool("debug-stock")
	chunks := superChunks(path)
	if dbg {
		fmt.Printf("[super] chunks=%d first=%q\n", len(chunks), firstOr(chunks))
	}
	if len(chunks) == 0 {
		return nil
	}
	// liblp metadata lives in the first ~1 MiB at the front of the first chunk;
	// pull just that window rather than expanding the whole 6+ GiB image.
	_, first, err := srcfile.Open(path, chunks[0])
	if err != nil {
		if dbg {
			fmt.Printf("[super] open %s: %v\n", chunks[0], err)
		}
		return nil
	}
	head := make([]byte, 1<<20)
	if _, err := sparse.CopyRange(first, 0, head); err != nil {
		if dbg {
			fmt.Printf("[super] read metadata window: %v\n", err)
		}
		return nil
	}
	if dbg {
		fmt.Printf("[super] metadata window isSuper=%v\n", lp.IsSuper(head))
	}
	meta, err := lp.Parse(head)
	if err != nil {
		if dbg {
			fmt.Printf("[super] lp.Parse: %v\n", err)
		}
		return nil
	}
	off, size := systemExtentLP(meta)
	if dbg {
		var names []string
		for _, p := range meta.Partitions {
			names = append(names, fmt.Sprintf("%s@%d/%dMB", p.Name, p.OffsetBytes>>20, p.SizeBytes>>20))
		}
		fmt.Printf("[super] parts: %s\n[super] system off=%d size=%d\n", strings.Join(names, " "), off, size)
	}
	if size == 0 {
		return nil
	}
	// The sparsechunks each address the whole image and carry real data only for
	// their own span, so overlay them: ask each for the system window and only the
	// owning chunk(s) write. Stop once the window is fully covered.
	sys := make([]byte, size)
	var covered int
	for i, name := range chunks {
		blob := first
		if i != 0 {
			_, blob, err = srcfile.Open(path, name)
			if err != nil {
				return nil
			}
		}
		w, err := sparse.CopyRange(blob, off, sys)
		if err != nil {
			return nil
		}
		covered += w
		if dbg && w > 0 {
			fmt.Printf("[super] %s wrote %d bytes of system window\n", name, w)
		}
		if uint64(covered) >= size {
			break
		}
	}
	if uint64(covered) < size {
		return nil // super truncated before system was fully covered
	}
	return propsFromSystemImage(sys)
}

// propsFromSystemImage reads the props from an in-memory system image (the super
// path holds the whole extent in one buffer). padReaderAt zero-fills reads past
// the image end so the EROFS reader can over-read its final physical cluster.
func propsFromSystemImage(sys []byte) map[string]string {
	return propsFromSystemImageAt(padReaderAt{sys})
}

// propsFromSystemImageAt reads the wanted build.prop lines out of a system
// partition image exposed as an io.ReaderAt. The partition is EROFS (the same
// read-only filesystem the device's kernel mounts), so it is read through the
// compressed EROFS reader; build.prop sits under system/ for a system-as-root
// image, or at the root of a legacy one.
func propsFromSystemImageAt(ra io.ReaderAt) map[string]string {
	dbg := v.GetBool("debug-stock")
	img, err := erofs.Open(ra)
	if err != nil {
		if dbg {
			fmt.Printf("[super] erofs.Open: %v\n", err)
		}
		return nil
	}
	for _, f := range []string{"system/build.prop", "build.prop", "system/system/build.prop"} {
		data, err := fs.ReadFile(img, f)
		if dbg {
			fmt.Printf("[super] read %s: err=%v len=%d\n", f, err, len(data))
		}
		if err != nil {
			continue
		}
		props := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			if k, val, ok := strings.Cut(strings.TrimSpace(line), "="); ok && val != "" && systemStockPropKeys[k] {
				props[k] = val
			}
		}
		if len(props) > 0 {
			return props
		}
	}
	return nil
}

// superChunks returns the package's super members in order: the sparsechunk
// series if present, else a single super.img.
func superChunks(path string) []string {
	chunks, _ := srcfile.Glob(path, "super.img_sparsechunk.*")
	if len(chunks) > 0 {
		sort.Slice(chunks, func(i, j int) bool { return chunkIndex(chunks[i]) < chunkIndex(chunks[j]) })
		return chunks
	}
	if _, _, err := srcfile.Open(path, "super.img"); err == nil {
		return []string{"super.img"}
	}
	return nil
}

// chunkIndex is the trailing integer of a sparsechunk name, so chunk 10 sorts
// after chunk 2 rather than lexically before it.
func chunkIndex(name string) int {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return 0
	}
	n, _ := strconv.Atoi(name[dot+1:])
	return n
}

// systemExtentLP returns the byte offset and size of the system volume in super.
// A package carries both slots; the A slot holds the shipped image (B is empty),
// so system_a is preferred, then a slotless system.
func systemExtentLP(meta *lp.Metadata) (offset, size uint64) {
	for _, want := range []string{"system_a", "system"} {
		for _, p := range meta.Partitions {
			if p.Name == want && p.OffsetBytes > 0 && p.SizeBytes > 0 {
				return p.OffsetBytes, p.SizeBytes
			}
		}
	}
	return 0, 0
}

func firstOr(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
