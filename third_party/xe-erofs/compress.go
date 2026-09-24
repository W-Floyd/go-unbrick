package erofs

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"

	"github.com/Xe/erofs/internal/ondisk"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// compressedFile implements fs.File for compressed EROFS files.
type compressedFile struct {
	fsys   *FS
	ino    *inode
	name   string
	offset int64
	closed bool

	// Compression metadata.
	mapHeader ondisk.MapHeader
	lclustSz  int64 // lcluster size in bytes

	// Cache for decompressed pcluster.
	cacheStart int64  // logical offset of cached extent start
	cacheEnd   int64  // logical offset of cached extent end
	cacheData  []byte // decompressed data
}

func (f *FS) openCompressedFile(ino *inode, name string) (fs.File, error) {
	// Read the compression map header.
	headerPos := align(ino.metaEnd(), 8)
	var mh ondisk.MapHeader
	buf := make([]byte, 8)
	if _, err := f.r.ReadAt(buf, headerPos); err != nil {
		return nil, fmt.Errorf("erofs: reading map header: %w", err)
	}
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &mh); err != nil {
		return nil, fmt.Errorf("erofs: decoding map header: %w", err)
	}

	lclustBits := f.blockSzBits + mh.LClusterBits()
	lclustSz := int64(1) << lclustBits

	return &compressedFile{
		fsys:      f,
		ino:       ino,
		name:      name,
		mapHeader: mh,
		lclustSz:  lclustSz,
	}, nil
}

func (cf *compressedFile) Stat() (fs.FileInfo, error) {
	return cf.ino.fileInfo(baseName(cf.name)), nil
}

func (cf *compressedFile) Read(p []byte) (int, error) {
	if cf.closed {
		return 0, fs.ErrClosed
	}
	if cf.offset >= int64(cf.ino.size) {
		return 0, io.EOF
	}

	n, err := cf.readAt(p, cf.offset)
	cf.offset += int64(n)
	return n, err
}

func (cf *compressedFile) Seek(offset int64, whence int) (int64, error) {
	if cf.closed {
		return 0, fs.ErrClosed
	}
	var newOff int64
	switch whence {
	case io.SeekStart:
		newOff = offset
	case io.SeekCurrent:
		newOff = cf.offset + offset
	case io.SeekEnd:
		newOff = int64(cf.ino.size) + offset
	default:
		return 0, fmt.Errorf("erofs: invalid whence %d", whence)
	}
	if newOff < 0 {
		return 0, fmt.Errorf("erofs: negative seek position")
	}
	cf.offset = newOff
	return newOff, nil
}

func (cf *compressedFile) Close() error {
	cf.closed = true
	cf.cacheData = nil
	return nil
}

func (cf *compressedFile) readAt(p []byte, off int64) (int, error) {
	if off >= int64(cf.ino.size) {
		return 0, io.EOF
	}

	remaining := int64(cf.ino.size) - off
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	total := 0
	for len(p) > 0 {
		// Check cache.
		if off >= cf.cacheStart && off < cf.cacheEnd && cf.cacheData != nil {
			cacheOff := off - cf.cacheStart
			n := copy(p, cf.cacheData[cacheOff:])
			total += n
			off += int64(n)
			p = p[n:]
			continue
		}

		// Decompress the pcluster covering this offset.
		if err := cf.loadPCluster(off); err != nil {
			return total, err
		}
		// The freshly loaded extent must cover off, or the loop would spin.
		if !(off >= cf.cacheStart && off < cf.cacheEnd && cf.cacheData != nil) {
			return total, fmt.Errorf("erofs: extent at off=%d did not cover it (cache [%d,%d))", off, cf.cacheStart, cf.cacheEnd)
		}
	}

	if off >= int64(cf.ino.size) {
		return total, io.EOF
	}
	return total, nil
}

// loadPCluster loads and decompresses the pcluster covering logical offset la.
func (cf *compressedFile) loadPCluster(la int64) error {
	ino := cf.ino

	// Determine index format.
	switch ino.dataLayout {
	case ondisk.InodeCompressedFull:
		return cf.loadPClusterFull(la)
	case ondisk.InodeCompressedCompact:
		return cf.loadPClusterCompact(la)
	default:
		return fmt.Errorf("erofs: unsupported compressed layout %d", ino.dataLayout)
	}
}

// loadPClusterFull handles the FULL index format (layout 1).
func (cf *compressedFile) loadPClusterFull(la int64) error {
	ino := cf.ino
	f := cf.fsys
	blockSize := int64(f.blockSize)

	// Index start: ALIGN(metaEnd, 8) + 8 (map header) + 8 (padding).
	indexStart := align(ino.metaEnd(), 8) + 8 + 8

	lcn := la / cf.lclustSz

	// Read the lcluster entry.
	entry, err := cf.readLClusterEntry(indexStart, lcn)
	if err != nil {
		return err
	}

	// A PLAIN lcluster carrying a non-zero clusterofs (in a non-interlaced
	// image) is a big-pcluster tail boundary marker: its bytes belong to the
	// preceding pcluster's extent. Resolve the offset there instead.
	if entry.Type() == ondisk.LClusterTypePlain && entry.ClusterOfs != 0 &&
		cf.mapHeader.Advise&ondisk.AdviseInterlacedPCluster == 0 && lcn > 0 {
		lcn--
		entry, err = cf.readLClusterEntry(indexStart, lcn)
		if err != nil {
			return err
		}
	}

	// Follow NONHEAD delta chain to find HEAD.
	headLcn := lcn
	for entry.Type() == ondisk.LClusterTypeNonHead {
		delta := int64(entry.Delta0())
		// On the first NONHEAD of a big pcluster, delta[0] carries the
		// compressed block count tagged with D0_CBLKCNT; the real backward
		// distance to the head is 1.
		if delta&ondisk.LID0CBlkCnt != 0 {
			delta = 1
		}
		if delta == 0 {
			return fmt.Errorf("erofs: zero delta in NONHEAD chain at lcn=%d", headLcn)
		}
		headLcn -= delta
		if headLcn < 0 {
			return fmt.Errorf("erofs: NONHEAD chain went negative at lcn=%d", lcn)
		}
		entry, err = cf.readLClusterEntry(indexStart, headLcn)
		if err != nil {
			return err
		}
	}

	// Determine algorithm.
	ltype := entry.Type()
	var algID uint8
	switch ltype {
	case ondisk.LClusterTypePlain:
		algID = 0xFF // plain/uncompressed
	case ondisk.LClusterTypeHead1:
		algID = cf.mapHeader.HeadAlgorithm()
	case ondisk.LClusterTypeHead2:
		algID = cf.mapHeader.Head2Algorithm()
	default:
		return fmt.Errorf("erofs: unexpected lcluster type %d", ltype)
	}

	pblk := int64(entry.BlkAddr())
	clusterOfs := int64(entry.ClusterOfs)

	// Determine pcluster size.
	// Check if big pcluster: look at next lcluster entry.
	pclusterBlocks := int64(1)
	nextLcn := headLcn + 1
	totalLclusters := (int64(ino.size) + cf.lclustSz - 1) / cf.lclustSz

	if nextLcn < totalLclusters {
		nextEntry, err := cf.readLClusterEntry(indexStart, nextLcn)
		if err == nil && nextEntry.Type() == ondisk.LClusterTypeNonHead &&
			nextEntry.Delta0()&ondisk.LID0CBlkCnt != 0 {
			// D0_CBLKCNT (bit 11) of the first NONHEAD's delta[0] carries the
			// pcluster's compressed block count.
			pclusterBlocks = int64(nextEntry.Delta0() &^ uint16(ondisk.LID0CBlkCnt))
		}
	}
	if pclusterBlocks < 1 {
		pclusterBlocks = 1
	}

	pclusterSize := pclusterBlocks * blockSize
	pa := pblk * blockSize

	// Determine decompressed extent boundaries.
	extentStart := headLcn*cf.lclustSz + clusterOfs
	// Find extent end: scan forward for next HEAD.
	extentEnd := int64(ino.size)
	for scanLcn := headLcn + 1; scanLcn < totalLclusters; scanLcn++ {
		scanEntry, err := cf.readLClusterEntry(indexStart, scanLcn)
		if err != nil {
			break
		}
		if scanEntry.Type() != ondisk.LClusterTypeNonHead {
			// The next non-NONHEAD entry marks the end of this extent; its
			// clusterofs is how far the extent reaches into that lcluster
			// (non-zero for a partial-tail boundary marker).
			extentEnd = scanLcn*cf.lclustSz + int64(scanEntry.ClusterOfs)
			break
		}
	}

	return cf.decodeExtent(ltype, algID, pa, pclusterSize, extentStart, extentEnd, clusterOfs)
}

// decodeExtent reads the physical pcluster [pa, pa+pclusterSize), turns it into
// the logical range [extentStart, extentEnd) — de-shifting a PLAIN extent or
// decompressing a HEAD one — and caches the result. Shared by the full and
// compact index paths, which differ only in how they resolve those parameters.
func (cf *compressedFile) decodeExtent(ltype, algID uint8, pa, pclusterSize, extentStart, extentEnd, clusterOfs int64) error {
	f := cf.fsys
	blockSize := int64(f.blockSize)

	decompSize := extentEnd - extentStart
	if decompSize <= 0 {
		decompSize = cf.lclustSz
	}

	compressed := make([]byte, pclusterSize)
	n, err := f.r.ReadAt(compressed, pa)
	if err != nil && n == 0 {
		return fmt.Errorf("erofs: reading pcluster at 0x%X: %w", pa, err)
	}
	compressed = compressed[:n]

	decompressed := make([]byte, decompSize)

	if ltype == ondisk.LClusterTypePlain {
		interlaced := cf.mapHeader.Advise&ondisk.AdviseInterlacedPCluster != 0
		if interlaced {
			pageofs := int(clusterOfs) % int(blockSize)
			if pageofs > 0 {
				tailLen := int(blockSize) - pageofs
				copy(decompressed, compressed[len(compressed)-tailLen:])
				copy(decompressed[tailLen:], compressed[:len(compressed)-tailLen])
			} else {
				copy(decompressed, compressed)
			}
		} else {
			// SHIFTED: skip clusterOfs bytes.
			copy(decompressed, compressed[clusterOfs:])
		}
	} else {
		// EROFS 0-padding: the compressed stream is right-aligned within its
		// physical blocks. Skip leading zero padding so the decoder sees the
		// stream start (the LZ4 token / zstd magic, never zero) and the exact
		// remaining length. (Older left-aligned images have no leading zeros,
		// so this is a no-op for them; lz4Decompress trims any trailing pad.)
		for len(compressed) > 0 && compressed[0] == 0 {
			compressed = compressed[1:]
		}
		switch algID {
		case ondisk.CompressionLZ4:
			dn, err := lz4Decompress(compressed, decompressed)
			if err != nil {
				return fmt.Errorf("erofs: lz4 decompress: %w", err)
			}
			decompressed = decompressed[:dn]
		case ondisk.CompressionDeflate:
			dn, err := deflateDecompress(compressed, decompressed)
			if err != nil {
				return fmt.Errorf("erofs: deflate decompress: %w", err)
			}
			decompressed = decompressed[:dn]
		case ondisk.CompressionZstd:
			dn, err := zstdDecompress(compressed, decompressed)
			if err != nil {
				return fmt.Errorf("erofs: zstd decompress: %w", err)
			}
			decompressed = decompressed[:dn]
		default:
			return fmt.Errorf("erofs: unsupported compression algorithm %d", algID)
		}
	}

	cf.cacheStart = extentStart
	cf.cacheEnd = extentStart + int64(len(decompressed))
	cf.cacheData = decompressed
	return nil
}

// loadPClusterCompact handles the COMPACT index format (layout 3).
// For now, fall back to reading the entries as if they were packed 4-byte entries.
// loadPClusterCompact handles the COMPACT (compacted 2B/4B) index format. It
// resolves the lcluster covering la to its head, sizes the pcluster and extent
// exactly as loadPClusterFull does, then hands off to decodeExtent. The index
// decode itself is loadCompactLcluster, a port of the kernel's
// z_erofs_load_compact_lcluster (fs/erofs/zmap.c).
func (cf *compressedFile) loadPClusterCompact(la int64) error {
	ino := cf.ino
	blockSize := int64(cf.fsys.blockSize)
	totalLclusters := (int64(ino.size) + cf.lclustSz - 1) / cf.lclustSz

	lcn := la / cf.lclustSz
	endoff := la % cf.lclustSz
	m, err := cf.loadCompactLcluster(lcn, totalLclusters)
	if err != nil {
		return err
	}

	// Resolve the extent's head lcluster, mirroring z_erofs_map_blocks_fo: this
	// lcluster is the head only if it is a HEAD/PLAIN whose data (at clusterofs)
	// starts at or before the wanted offset; otherwise la belongs to an earlier
	// extent and we walk back (z_erofs_extent_lookback) to its head. A HEAD/PLAIN
	// whose data starts past endoff is a mid-lcluster boundary — la is the prior
	// extent's tail, one lcluster back.
	headLcn := lcn
	if m.typ == ondisk.LClusterTypeNonHead || endoff < m.clusterofs {
		dist := m.delta0
		if m.typ != ondisk.LClusterTypeNonHead {
			if lcn == 0 {
				return fmt.Errorf("erofs: compact head at lcn 0 with clusterofs > offset")
			}
			dist = 1
		}
		for {
			if dist == 0 {
				return fmt.Errorf("erofs: zero lookback distance at lcn=%d", headLcn)
			}
			headLcn -= dist
			if headLcn < 0 {
				return fmt.Errorf("erofs: compact lookback went negative from lcn=%d", lcn)
			}
			if m, err = cf.loadCompactLcluster(headLcn, totalLclusters); err != nil {
				return err
			}
			if m.typ == ondisk.LClusterTypeNonHead {
				dist = m.delta0
				continue
			}
			break
		}
	}

	ltype := m.typ
	var algID uint8
	switch ltype {
	case ondisk.LClusterTypePlain:
		algID = 0xFF
	case ondisk.LClusterTypeHead1:
		algID = cf.mapHeader.HeadAlgorithm()
	case ondisk.LClusterTypeHead2:
		algID = cf.mapHeader.Head2Algorithm()
	default:
		return fmt.Errorf("erofs: unexpected compact lcluster type %d", ltype)
	}

	pblk := m.pblk
	clusterOfs := m.clusterofs

	// pcluster block count: for a big pcluster the first following NONHEAD
	// carries the compressed block count (D0_CBLKCNT); otherwise it is one block.
	pclusterBlocks := int64(1)
	if headLcn+1 < totalLclusters {
		if nx, err := cf.loadCompactLcluster(headLcn+1, totalLclusters); err == nil &&
			nx.typ == ondisk.LClusterTypeNonHead && nx.compressedblks > 0 {
			pclusterBlocks = nx.compressedblks
		}
	}

	pa := pblk * blockSize
	pclusterSize := pclusterBlocks * blockSize

	// Extent boundaries: forward-scan for the next non-NONHEAD.
	extentStart := headLcn*cf.lclustSz + clusterOfs
	extentEnd := int64(ino.size)
	for scanLcn := headLcn + 1; scanLcn < totalLclusters; scanLcn++ {
		sm, err := cf.loadCompactLcluster(scanLcn, totalLclusters)
		if err != nil {
			break
		}
		if sm.typ != ondisk.LClusterTypeNonHead {
			extentEnd = scanLcn*cf.lclustSz + sm.clusterofs
			break
		}
	}

	return cf.decodeExtent(ltype, algID, pa, pclusterSize, extentStart, extentEnd, clusterOfs)
}

// compactLcluster is one decoded compacted-index entry — the fields the kernel's
// z_erofs_maprecorder exposes, normalized to bytes.
type compactLcluster struct {
	typ            uint8
	clusterofs     int64
	pblk           int64 // physical block address (HEAD / PLAIN)
	delta0         int64 // backward distance to the head (NONHEAD)
	compressedblks int64 // pcluster block count, set on the first NONHEAD of a big pcluster
}

// loadCompactLcluster decodes the compacted index entry for lcn — a faithful
// port of the kernel's z_erofs_load_compact_lcluster + unpack_compacted_index
// (fs/erofs/zmap.c). Lookahead (delta[1]) is omitted: the reader never needs it.
func (cf *compressedFile) loadCompactLcluster(lcn, totalidx int64) (compactLcluster, error) {
	var m compactLcluster
	f := cf.fsys
	lclusterbits := int(f.blockSzBits) + int(cf.mapHeader.LClusterBits())
	if lcn >= totalidx || lclusterbits > 14 {
		return m, fmt.Errorf("erofs: compact lcn %d out of range", lcn)
	}

	// ebase = Z_EROFS_MAP_HEADER_END = ALIGN(metaEnd, 8) + map header (8 bytes).
	ebase := align(cf.ino.metaEnd(), 8) + 8
	compacted4bInitial := ((32 - ebase%32) / 4) & 7
	var compacted2b int64
	if cf.mapHeader.Advise&ondisk.AdviseCompacted2B != 0 && compacted4bInitial < totalidx {
		compacted2b = ((totalidx - compacted4bInitial) / 16) * 16
	}

	pos := ebase
	amortizedshift := int64(2) // compact_4b
	rel := lcn
	if rel >= compacted4bInitial {
		pos += compacted4bInitial * 4
		rel -= compacted4bInitial
		if rel < compacted2b {
			amortizedshift = 1
		} else {
			pos += compacted2b * 2
			rel -= compacted2b
		}
	}
	pos += rel * (1 << amortizedshift)

	// lclusters per pack.
	var vcnt int64
	switch {
	case (1<<amortizedshift) == 4 && lclusterbits <= 14:
		vcnt = 2
	case (1<<amortizedshift) == 2 && lclusterbits <= 12:
		vcnt = 16
	default:
		return m, fmt.Errorf("erofs: unsupported compact packing (shift=%d bits=%d)", amortizedshift, lclusterbits)
	}

	packLen := vcnt << amortizedshift
	lobits := lclusterbits
	if lobits < 12 { // ilog2(LID0CBlkCnt)+1 == 12
		lobits = 12
	}
	encodebits := int((packLen - 4) * 8 / vcnt)

	packStart := pos &^ (packLen - 1)
	pack := make([]byte, packLen)
	if _, err := f.r.ReadAt(pack, packStart); err != nil {
		return m, fmt.Errorf("erofs: reading compact pack: %w", err)
	}
	i := int((pos - packStart) >> amortizedshift)
	bigPcluster := cf.mapHeader.Advise&ondisk.AdviseBigPCluster1 != 0

	lo, typ := decodeCompactedBits(lobits, pack, encodebits*i)
	m.typ = typ
	if typ == ondisk.LClusterTypeNonHead {
		m.clusterofs = int64(1) << lclusterbits
		if lo&ondisk.LID0CBlkCnt != 0 {
			if !bigPcluster {
				return m, fmt.Errorf("erofs: D0_CBLKCNT set without big pcluster")
			}
			m.compressedblks = int64(lo &^ uint32(ondisk.LID0CBlkCnt))
			m.delta0 = 1
			return m, nil
		}
		if i+1 != int(vcnt) {
			m.delta0 = int64(lo)
			return m, nil
		}
		// The last lcluster in a pack stores delta[1]; recover delta[0] from the
		// previous entry.
		lo2, t2 := decodeCompactedBits(lobits, pack, encodebits*(i-1))
		switch {
		case t2 != ondisk.LClusterTypeNonHead:
			lo2 = 0
		case lo2&ondisk.LID0CBlkCnt != 0:
			lo2 = 1
		}
		m.delta0 = int64(lo2) + 1
		return m, nil
	}

	m.clusterofs = int64(lo)

	// Physical block: the pack's trailing base blkaddr plus the HEAD blocks
	// accumulated backward through the pack.
	var nblk int64
	if !bigPcluster {
		nblk = 1
		for i > 0 {
			i--
			l, t := decodeCompactedBits(lobits, pack, encodebits*i)
			if t == ondisk.LClusterTypeNonHead {
				i -= int(l)
			}
			if i >= 0 {
				nblk++
			}
		}
	} else {
		for i > 0 {
			i--
			l, t := decodeCompactedBits(lobits, pack, encodebits*i)
			if t == ondisk.LClusterTypeNonHead {
				if l&ondisk.LID0CBlkCnt != 0 {
					i--
					nblk += int64(l &^ uint32(ondisk.LID0CBlkCnt))
					continue
				}
				if l <= 1 {
					return m, fmt.Errorf("erofs: corrupt big-pcluster delta %d", l)
				}
				i -= int(l) - 2
				continue
			}
			nblk++
		}
	}
	m.pblk = int64(le32(pack[packLen-4:])) + nblk
	return m, nil
}

// decodeCompactedBits reads the lo-bits value and 2-bit type at bit offset
// posBits within a compacted pack (kernel decode_compactedbits).
func decodeCompactedBits(lobits int, pack []byte, posBits int) (lo uint32, typ uint8) {
	v := le32(pack[posBits/8:]) >> uint(posBits%8)
	lo = v & ((1 << lobits) - 1)
	typ = uint8((v >> lobits) & 3)
	return lo, typ
}

// readLClusterEntry reads a single lcluster index entry in FULL format.
func (cf *compressedFile) readLClusterEntry(indexStart, lcn int64) (ondisk.LClusterIndex, error) {
	off := indexStart + lcn*8
	buf := make([]byte, 8)
	if _, err := cf.fsys.r.ReadAt(buf, off); err != nil {
		return ondisk.LClusterIndex{}, err
	}
	return ondisk.LClusterIndex{
		Advise:     le16(buf[0:2]),
		ClusterOfs: le16(buf[2:4]),
		Union:      le32(buf[4:8]),
	}, nil
}

// lz4Decompress decompresses LZ4 block data.
func lz4Decompress(src, dst []byte) (int, error) {
	// Trim trailing zeros if present (ZERO_PADDING feature).
	trimmed := src
	for len(trimmed) > 0 && trimmed[len(trimmed)-1] == 0 {
		trimmed = trimmed[:len(trimmed)-1]
	}
	if len(trimmed) == 0 {
		return 0, nil
	}

	n, err := lz4.UncompressBlock(trimmed, dst)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// zstdDecompress decompresses ZSTD data.
func zstdDecompress(src, dst []byte) (int, error) {
	r, err := zstd.NewReader(bytes.NewReader(src), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return 0, err
	}
	defer r.Close()
	n, err := io.ReadFull(r, dst)
	// The pcluster is zero-padded past the end of the zstd frame; once we
	// have read the expected decompressed size we stop and ignore the rest.
	if err == io.ErrUnexpectedEOF {
		return n, nil
	}
	return n, err
}

// deflateDecompress decompresses DEFLATE data.
func deflateDecompress(src, dst []byte) (int, error) {
	r := flate.NewReader(bytes.NewReader(src))
	defer r.Close()
	n, err := io.ReadFull(r, dst)
	if err == io.ErrUnexpectedEOF {
		return n, nil
	}
	return n, err
}
