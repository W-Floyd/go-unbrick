package carve

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/W-Floyd/erofs"
	"github.com/pierrec/lz4/v4"

	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/bootelf"
	"github.com/W-Floyd/go-unbrick/internal/bootimg"
	"github.com/W-Floyd/go-unbrick/internal/dtbo"
	"github.com/W-Floyd/go-unbrick/internal/ext4fs"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/lp"
	"github.com/W-Floyd/go-unbrick/internal/modem"
	"github.com/W-Floyd/go-unbrick/internal/payload"
	"github.com/W-Floyd/go-unbrick/internal/qcdt"
	"github.com/W-Floyd/go-unbrick/internal/sparse"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/tgzseek"
	"github.com/W-Floyd/go-unbrick/internal/ubi"
	"github.com/W-Floyd/go-unbrick/internal/ubifs"
)

func init() {
	Register(
		// The input itself, when it is an archive: srcfile knows how to reach
		// the members of a remote one cheaply.
		Expander{Kind: "archive", Match: func(n *Node, _ []byte) bool { return n.path != "" && srcfile.IsArchive(n.path) }, Expand: expandInput},
		Expander{Kind: "zip", Match: kind(filetype.Zip), Expand: expandZip},
		// Before tar: a deflated one is entered mid-stream, not buffered whole.
		Expander{Kind: "tar", Match: func(n *Node, h []byte) bool { return filetype.Detect(h) == filetype.Tar && n.deflated() != nil }, Expand: expandDeflatedTar},
		Expander{Kind: "tar", Match: kind(filetype.Tar), Expand: expandTar},
		// Before gzip: a boot image's ramdisk is often gzip, and is a cpio.
		Expander{Kind: "ramdisk", Match: isRamdisk, Expand: expandRamdisk},
		Expander{Kind: "gzip", Match: kind(filetype.Gzip), Expand: expandGzip},
		Expander{Kind: "lz4", Match: kind(filetype.LZ4), Expand: expandLZ4},
		Expander{Kind: "payload", Match: kind(filetype.OTAPayload), Expand: expandPayload},
		Expander{Kind: "sparse", Match: kind(filetype.SparseImage), Expand: expandSparse},
		Expander{Kind: "super", Match: func(_ *Node, h []byte) bool { return lp.IsSuper(h) }, Expand: expandSuper},
		Expander{Kind: "fat", Match: kind(filetype.FAT), Expand: expandFirmwareFS, FS: firmwareFS},
		Expander{Kind: "ext4", Match: kind(filetype.Ext4), Expand: expandExt4, FS: ext4FS},
		Expander{Kind: "erofs", Match: kind(filetype.EROFS), Expand: expandEROFS, FS: erofsFS},
		Expander{Kind: "boot", Match: kind(filetype.AndroidBoot, filetype.AndroidVendorBoot), Expand: expandBoot},
		Expander{Kind: "single_n_lonely", Match: kind(filetype.SingleNLonely), Expand: expandSingleNLonely},
		Expander{Kind: "dtbo", Match: kind(filetype.DTBOTable), Expand: expandDTBO},
		Expander{Kind: "odex", Match: kind(filetype.ODEX), Expand: expandODEX},
		Expander{Kind: "qcdt", Match: kind(filetype.QCDT), Expand: expandQCDT},
		Expander{Kind: "zimage", Match: func(_ *Node, h []byte) bool { return bootimg.IsZImage(h) }, Expand: expandZImage},
		Expander{Kind: "ubi", Match: kind(filetype.UBI), Expand: expandUBI},
		Expander{Kind: "ubifs", Match: kind(filetype.UBIFS), Expand: expandUBIFS, FS: ubifsFS},
	)
}

// expandODEX lists the DEX an optimized-DEX file wraps: its header (magic,
// version, then little-endian dexOffset and dexLength) bounds the DEX, which
// is followed by the dependency and optimization tables.
func expandODEX(n *Node) ([]*Node, error) {
	// The header says where the dex sits; the rest of the file is read only if
	// someone reads the dex.
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, err
	}
	var h [16]byte
	if _, err := ra.ReadAt(h[:], 0); err != nil {
		return nil, fmt.Errorf("odex: truncated header")
	}
	off, size := int64(binary.LittleEndian.Uint32(h[8:])), int64(binary.LittleEndian.Uint32(h[12:]))
	if off+size > n.Size {
		return nil, fmt.Errorf("odex: dex range [%d:%d] runs past the file", off, off+size)
	}
	name := strings.TrimSuffix(path.Base(n.Name), path.Ext(n.Name)) + ".dex"
	return []*Node{FromReaderAt(name, io.NewSectionReader(ra, off, size), size)}, nil
}

// expandQCDT lists the device trees of a Qualcomm DT table, named by the board
// each is for.
func expandQCDT(n *Node) ([]*Node, error) {
	b, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	es, err := qcdt.Parse(b)
	if err != nil {
		return nil, err
	}
	var out []*Node
	for i, e := range es {
		out = append(out, FromBytes(fmt.Sprintf("%02d-plat%x-var%x-rev%x.dtb", i, e.Platform, e.Variant, e.SoCRev), e.DTB))
	}
	return out, nil
}

// expandZImage lists the kernel an ARM zImage decompresses to, and the build
// config it embeds when it has one.
func expandZImage(n *Node) ([]*Node, error) {
	b, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	plain, err := bootimg.ZImagePayload(b)
	if err != nil {
		return nil, err
	}
	out := []*Node{FromBytes("Image", plain)}
	if cfg, ok := bootimg.KernelConfig(plain); ok {
		out = append(out, FromBytes("config", cfg))
	}
	return out, nil
}

func ubifsFS(n *Node) (fs.FS, error) {
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, err
	}
	return ubifs.Open(ra, n.Size)
}

func expandUBIFS(n *Node) ([]*Node, error) {
	img, err := ubifsFS(n)
	if err != nil {
		return nil, err
	}
	return walkFS(img)
}

// walkFS lists a filesystem's regular files, reading each by path on demand,
// and adds each PIL split (an .mdt with its .bNN segments) joined into the ELF
// it was split from as "<name>.mdt.joined", as expandFirmwareFS does.
func walkFS(inner fs.FS) ([]*Node, error) {
	// Every node made here reads through this one lock: see lockedFS.
	img := lockFS(inner)
	var out []*Node
	err := fs.WalkDir(img, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if img.oa != nil {
			// A filesystem that reads files at random hands them out that way, so
			// a zip's directory is read without the rest of it.
			out = append(out, FromReaderAt(p, img.openAt(p), info.Size()))
		} else {
			out = append(out, FromStream(p, info.Size(), func() (io.ReadCloser, error) { return img.Open(p) }))
		}
		if strings.EqualFold(path.Ext(p), ".mdt") {
			head, err := fs.ReadFile(img, p)
			if err != nil {
				return nil
			}
			stem := strings.TrimSuffix(p, path.Ext(p))
			joined, _, err := bootelf.JoinSplit(head, func(i int) []byte {
				b, _ := fs.ReadFile(img, fmt.Sprintf("%s.b%02d", stem, i))
				return b
			})
			if err == nil {
				out = append(out, FromBytes(p+".joined", joined))
			}
		}
		return nil
	})
	return out, err
}

func expandUBI(n *Node) ([]*Node, error) {
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, err
	}
	im, err := ubi.Parse(ra, n.Size)
	if err != nil {
		return nil, err
	}
	var out []*Node
	for _, v := range im.Volumes {
		out = append(out, FromReaderAt(v.Name, v.ReaderAt(), v.Size))
	}
	return out, nil
}

func kind(ks ...filetype.Kind) func(*Node, []byte) bool {
	return func(_ *Node, h []byte) bool {
		d := filetype.Detect(h)
		for _, k := range ks {
			if d == k {
				return true
			}
		}
		return false
	}
}

func expandInput(n *Node) ([]*Node, error) {
	es, _, err := srcfile.Entries(n.path) // held open for the process
	if err != nil {
		return nil, err
	}
	var out []*Node
	for _, e := range es {
		var k *Node
		if e.At != nil {
			k = FromReaderAt(e.Name, e.At, int64(e.Size))
		} else {
			k = FromStream(e.Name, int64(e.Size), e.Open)
			k.defl = e.Deflate
			if e.DeflateFn != nil {
				k.deflFn = e.DeflateFn
			}
		}
		if e.HasCRC {
			withClaim(k, "crc32", fmt.Sprintf("%08x", e.CRC32), int64(e.Size))
		}
		switch {
		case e.HasSrc:
			k.src = &source{path: n.path, off: e.SrcOff, length: e.SrcLen}
		case e.SrcFn != nil: // where it sits is found when asked (see Node.Source)
			k.srcFn = e.SrcFn
			k.srcPath = n.path
		}
		k.Modified = e.Modified
		out = append(out, k)
	}
	return joinSuperChunks(out), nil
}

func expandZip(n *Node) ([]*Node, error) {
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(ra, n.Size)
	if err != nil {
		return nil, err
	}
	var out []*Node
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		crc := fmt.Sprintf("%08x", f.CRC32)
		size := int64(f.UncompressedSize64)
		// An encrypted member is opened with the vendor's password, when it has one.
		if k := decryptedZipMember(n, f, ra); k != nil {
			out = append(out, k)
			continue
		}
		// Where a member's data starts is in its local header, a read of its own:
		// done when the member is read, not once per member of every zip listed.
		if f.Method == zip.Store {
			k := withClaim(FromReaderAt(f.Name, &zipStored{f: f, ra: ra, size: size}, size), "crc32", crc, size)
			k.Modified = f.Modified
			out = append(out, k)
			continue
		}
		open := func() (io.ReadCloser, error) { return f.Open() }
		k := FromStream(f.Name, size, open)
		if f.Method == zip.Deflate {
			k.deflFn = func() *srcfile.Deflated {
				off, err := f.DataOffset()
				if err != nil {
					return nil
				}
				return &srcfile.Deflated{R: ra, Start: off, End: off + int64(f.CompressedSize64)}
			}
		}
		k.Modified = f.Modified
		out = append(out, withClaim(k, "crc32", crc, size))
	}
	return joinSuperChunks(out), nil
}

// zipStored reads a stored zip member at random, finding where its data starts
// on first use.
type zipStored struct {
	f    *zip.File
	ra   io.ReaderAt
	size int64

	once sync.Once
	sec  io.ReaderAt
	err  error
}

func (z *zipStored) ReadAt(p []byte, off int64) (int, error) {
	z.once.Do(func() {
		start, err := z.f.DataOffset()
		if err != nil {
			z.err = err
			return
		}
		z.sec = io.NewSectionReader(z.ra, start, z.size)
	})
	if z.err != nil {
		return 0, z.err
	}
	return z.sec.ReadAt(p, off)
}

// expandDeflatedTar lists a tar held deflated in a zip without decoding it
// through: an Odin .tar.md5 is gigabytes of lz4 images.
func expandDeflatedTar(n *Node) ([]*Node, error) {
	d := n.deflated()
	a, err := tgzseek.OpenDeflate(d.R, d.Start, d.End, n.Size)
	if err != nil {
		return nil, err
	}
	if !a.Complete {
		n.partial = a.String()
	}
	var out []*Node
	for i, e := range a.Entries {
		k := FromStream(e.Name, e.Size, func() (io.ReadCloser, error) { return io.NopCloser(a.Open(i)), nil })
		if int64(len(e.Head)) == e.Size || len(e.Head) >= headLen {
			k.head = e.Head[:min(len(e.Head), headLen)]
		}
		out = append(out, k)
	}
	return out, nil
}

// expandLZ4 has one child, the decompressed frame, named without ".lz4".
func expandLZ4(n *Node) ([]*Node, error) {
	name := strings.TrimSuffix(path.Base(n.Name), ".lz4")
	if name == path.Base(n.Name) {
		name += ".out"
	}
	size := int64(-1)
	if h := n.Head(); len(h) >= 14 && h[4]&0x08 != 0 { // FLG.ContentSize
		size = int64(binary.LittleEndian.Uint64(h[6:14]))
	}
	open := func() (io.ReadCloser, error) {
		rc, err := n.Reader()
		if err != nil {
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{lz4.NewReader(rc), rc}, nil
	}
	return []*Node{FromStream(name, size, open)}, nil
}

// expandTar indexes a tar: tar.Reader seeks past each body, so every member
// is a section of the parent.
func expandTar(n *Node) ([]*Node, error) {
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, err
	}
	sr := io.NewSectionReader(ra, 0, n.Size)
	tr := tar.NewReader(sr)
	var out []*Node
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		off, _ := sr.Seek(0, io.SeekCurrent)
		out = append(out, FromReaderAt(h.Name, io.NewSectionReader(ra, off, h.Size), h.Size))
	}
}

// expandGzip has one child, the decompressed stream, named as gzip names it.
func expandGzip(n *Node) ([]*Node, error) {
	name := strings.TrimSuffix(path.Base(n.Name), ".gz")
	if strings.HasSuffix(name, ".tgz") {
		name = strings.TrimSuffix(name, ".tgz") + ".tar"
	}
	if name == path.Base(n.Name) {
		name += ".out"
	}
	open := func() (io.ReadCloser, error) {
		rc, err := n.Reader()
		if err != nil {
			return nil, err
		}
		z, err := gzip.NewReader(rc)
		if err != nil {
			rc.Close()
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{z, rc}, nil
	}
	return []*Node{FromStream(name, -1, open)}, nil
}

func expandPayload(n *Node) ([]*Node, error) {
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, err
	}
	p, err := payload.NewFromReaderAt(ra, n.Size)
	if err != nil {
		return nil, err
	}
	var out []*Node
	for _, name := range p.Partitions() {
		pra, size, err := p.PartitionReaderAt(name)
		if err != nil {
			continue // a delta partition, which needs the old image to apply
		}
		k := FromReaderAt(name, pra, size)
		// The manifest states the SHA-256 of the partition as installed.
		if info := p.Partition(name).GetNewPartitionInfo(); len(info.GetHash()) == sha256.Size && int64(info.GetSize()) == size {
			withClaim(k, "sha256", hex.EncodeToString(info.GetHash()), size)
		}
		out = append(out, k)
	}
	return out, nil
}

// expandSparse presents the raw image as one child, read by range off the sparse
// blob rather than materialized — so a multi-GiB ext4/erofs inside a sparse image
// is walked lazily by the filesystem expanders, not buffered whole.
func expandSparse(n *Node) ([]*Node, error) {
	if n.Size > MaxBuffer {
		// Too big to hold: read it where it is (a stored member in place, or the
		// temporary file --full-download unpacks it to), through the overlay a
		// split image's chunks use, which takes one sparse file as readily.
		ra, err := n.ReaderAt()
		if err != nil {
			return nil, err
		}
		o, err := sparse.NewOverlay([]io.ReaderAt{ra})
		if err != nil {
			return nil, err
		}
		return []*Node{FromReaderAt("unsparsed", o, o.Size())}, nil
	}
	b, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	ra, size, err := sparse.ReaderAt(b)
	if err != nil {
		return nil, err
	}
	return []*Node{FromReaderAt("unsparsed", ra, size)}, nil
}

// expandSuper maps super's logical partitions through their extents.
func expandSuper(n *Node) ([]*Node, error) {
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, err
	}
	meta := make([]byte, min(n.Size, 1<<20))
	if _, err := ra.ReadAt(meta, 0); err != nil && err != io.EOF {
		return nil, err
	}
	md, err := lp.Parse(meta)
	if err != nil {
		return nil, err
	}
	var out []*Node
	for _, p := range md.Partitions {
		if p.SizeBytes == 0 {
			continue
		}
		var parts []extent
		for _, e := range p.Extents {
			parts = append(parts, extent{ra: ra, off: int64(e.Offset), size: int64(e.Size), zero: !e.Linear})
		}
		out = append(out, FromReaderAt(p.Name, &concat{parts: parts}, int64(p.SizeBytes)))
	}
	return out, nil
}

// expandFirmwareFS lists a FAT or ext4 image's files, and adds each PIL split
// (an .mdt with its .bNN segments) joined into the ELF it was split from, as
// "<name>.mdt.joined".
func expandFirmwareFS(n *Node) ([]*Node, error) {
	img, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	entries, err := modem.List(img)
	if err != nil {
		return nil, err
	}
	var out []*Node
	for _, e := range entries {
		p := e.Path
		out = append(out, FromStream(p, int64(e.Size), func() (io.ReadCloser, error) {
			b, err := modem.Extract(img, p)
			return io.NopCloser(bytes.NewReader(b)), err
		}))
		if strings.EqualFold(path.Ext(p), ".mdt") {
			if joined, _, err := modem.JoinSplit(img, p); err == nil {
				out = append(out, FromBytes(p+".joined", joined))
			}
		}
	}
	return out, nil
}

// ext4FS reads an ext4 image in place: a file is reached through the
// directories on its path, not by holding the image.
func ext4FS(n *Node) (fs.FS, error) {
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, err
	}
	return ext4fs.Open(ra, n.Size)
}

// maxFirmwareImage is the largest ext4 image listed as a firmware image is
// (in memory, its split .mdt images joined); a partition past it is walked
// in place.
const maxFirmwareImage = 256 << 20

func expandExt4(n *Node) ([]*Node, error) {
	if n.Size <= maxFirmwareImage {
		return expandFirmwareFS(n)
	}
	img, err := ext4FS(n)
	if err != nil {
		return nil, err
	}
	return walkFS(img)
}

func erofsFS(n *Node) (fs.FS, error) {
	ra, err := n.ReaderAt()
	if err != nil {
		return nil, err
	}
	return erofs.Open(padReaderAt{ra})
}

func expandEROFS(n *Node) ([]*Node, error) {
	img, err := erofsFS(n)
	if err != nil {
		return nil, err
	}
	return walkFS(img)
}

func expandBoot(n *Node) ([]*Node, error) {
	b, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	im, err := bootimg.Parse(b)
	if err != nil {
		return nil, err
	}
	var out []*Node
	for _, s := range im.Sections {
		out = append(out, FromBytes(s.Name, s.Data))
	}
	return out, nil
}

// isRamdisk claims a boot image's ramdisk section, however compressed, and
// any plain cpio archive.
func isRamdisk(n *Node, h []byte) bool {
	return bytes.HasPrefix(h, []byte("070701")) || bytes.HasPrefix(h, []byte("070702")) ||
		strings.Contains(n.Name, "ramdisk") && bootimg.DetectCodec(h) != ""
}

func expandRamdisk(n *Node) ([]*Node, error) {
	b, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(b, []byte("0707")) {
		if b, _, err = bootimg.DecompressRamdisk(b); err != nil {
			return nil, err
		}
	}
	entries, err := bootimg.ParseCpioConcat(b)
	if err != nil {
		return nil, err
	}
	var out []*Node
	for _, e := range entries {
		if e.IsDir || e.IsLink || e.Name == "TRAILER!!!" {
			continue
		}
		out = append(out, FromBytes(e.Name, e.Data))
	}
	return out, nil
}

func expandSingleNLonely(n *Node) ([]*Node, error) {
	b, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	recs, err := blankflash.Parse(b)
	if err != nil {
		return nil, err
	}
	var out []*Node
	for _, r := range recs {
		out = append(out, FromBytes(r.Name, r.Data))
	}
	return out, nil
}

func expandDTBO(n *Node) ([]*Node, error) {
	b, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	t, err := dtbo.Parse(b)
	if err != nil {
		return nil, err
	}
	var out []*Node
	for i, e := range t.Entries {
		if int(e.Offset)+int(e.Size) > len(b) {
			return out, fmt.Errorf("dtbo entry %d runs past the image", i)
		}
		out = append(out, FromBytes(fmt.Sprintf("%02d-id%x-rev%x.dtb", i, e.ID, e.Rev), b[e.Offset:e.Offset+e.Size]))
	}
	return out, nil
}

// extent is one run of a logical partition: bytes of super, or zeros.
type extent struct {
	ra        io.ReaderAt
	off, size int64
	zero      bool
}

// concat reads extents end to end as one image.
type concat struct{ parts []extent }

func (c *concat) ReadAt(p []byte, off int64) (int, error) {
	n := 0
	for _, e := range c.parts {
		if off >= e.size {
			off -= e.size
			continue
		}
		k := int(min(int64(len(p)-n), e.size-off))
		if e.zero {
			clear(p[n : n+k])
		} else if _, err := e.ra.ReadAt(p[n:n+k], e.off+off); err != nil && err != io.EOF {
			return n, err
		}
		n += k
		off = 0
		if n == len(p) {
			return n, nil
		}
	}
	return n, io.EOF
}

// padReaderAt zero-fills reads past the end, which the EROFS reader makes
// when it over-reads a final physical cluster.
type padReaderAt struct{ io.ReaderAt }

func (p padReaderAt) ReadAt(b []byte, off int64) (int, error) {
	n, err := p.ReaderAt.ReadAt(b, off)
	if err == io.EOF {
		clear(b[n:])
		return len(b), nil
	}
	return n, err
}

var superChunk = regexp.MustCompile(`^super\.img_sparsechunk\.(\d+)$`)

// joinSuperChunks replaces a package's super.img_sparsechunk.N members with one
// super.img node reading them as the image they overlay into. Its size is the
// first chunk's declared image size; the chunks are only read, and if deflated
// spooled to temp files, when something reads the image.
func joinSuperChunks(nodes []*Node) []*Node {
	var chunks, out []*Node
	for _, n := range nodes {
		if superChunk.MatchString(path.Base(n.Name)) {
			chunks = append(chunks, n)
		} else {
			out = append(out, n)
		}
	}
	if len(chunks) == 0 {
		return nodes
	}
	idx := func(n *Node) int { i, _ := strconv.Atoi(superChunk.FindStringSubmatch(path.Base(n.Name))[1]); return i }
	sort.Slice(chunks, func(i, j int) bool { return idx(chunks[i]) < idx(chunks[j]) })
	size, err := sparseImageSize(chunks[0])
	if err != nil {
		return nodes
	}
	return append(out, FromReaderAt("super.img", &lazyOverlay{chunks: chunks}, size))
}

// sparseImageSize reads the raw image size a sparse node's header declares.
func sparseImageSize(n *Node) (int64, error) {
	rc, err := n.Reader()
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	h := make([]byte, 28)
	if _, err := io.ReadFull(rc, h); err != nil {
		return 0, err
	}
	if !sparse.IsSparse(h) {
		return 0, fmt.Errorf("%s is not sparse", n.Name)
	}
	return int64(binary.LittleEndian.Uint32(h[16:])) * int64(binary.LittleEndian.Uint32(h[12:])), nil
}

// lazyOverlay is sparse.Overlay over chunk nodes, built on first read. A chunk
// that cannot be read at random is spooled to an unlinked temp file.
type lazyOverlay struct {
	chunks []*Node
	once   sync.Once
	o      *sparse.Overlay
	err    error
}

// Progress, when set, is told about work too slow to be silent (unpacking a
// multi-gigabyte image to a temporary file). The command line points it at
// stderr; a library user leaves it nil.
var Progress func(format string, args ...any)

func progress(format string, args ...any) {
	if Progress != nil {
		Progress(format, args...)
	}
}

// spoolWorkers is how many chunks are unpacked at once.
const spoolWorkers = 4

func (l *lazyOverlay) ReadAt(p []byte, off int64) (int, error) {
	l.once.Do(func() {
		files := make([]io.ReaderAt, len(l.chunks))
		var todo []int
		for i, c := range l.chunks {
			if at, _ := c.random(); at != nil {
				files[i] = at
			} else {
				todo = append(todo, i)
			}
		}
		if len(todo) > 0 {
			progress("unpacking the super image, a few GB in %s", os.TempDir())
			var (
				wg   sync.WaitGroup
				mu   sync.Mutex
				done int
				sem  = make(chan struct{}, spoolWorkers)
			)
			for _, i := range todo {
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					f, err := spool(l.chunks[i])
					mu.Lock()
					defer mu.Unlock()
					if err != nil {
						if l.err == nil {
							l.err = err
						}
						return
					}
					files[i] = f
					done++
					if done%11 == 0 || done == len(todo) {
						progress("  unpacked %d of %d chunks", done, len(todo))
					}
				}()
			}
			wg.Wait()
			if l.err != nil {
				return
			}
		}
		l.o, l.err = sparse.NewOverlay(files)
	})
	if l.err != nil {
		return 0, l.err
	}
	return l.o.ReadAt(p, off)
}

func spool(n *Node) (*os.File, error) {
	rc, err := n.Reader()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	f, err := os.CreateTemp("", "unbrick-spool-*")
	if err != nil {
		return nil, err
	}
	os.Remove(f.Name()) // gone once closed; Windows keeps it until exit
	if _, err := io.Copy(f, rc); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", n.Name, err)
	}
	return f, nil
}
