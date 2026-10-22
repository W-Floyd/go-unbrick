package analysis

import "math"

// EntropyProfile rates how random a file's bytes look: Shannon entropy over the
// whole sample, and per block so a file that is only partly ciphertext shows it.
type EntropyProfile struct {
	Bits   float64   `json:"bits"`   // bits per byte, 0..8
	Blocks []float64 `json:"blocks"` // bits per byte of each block, in file order
	Block  int       `json:"block"`  // bytes per block
	Class  string    `json:"class"`  // random, high, mixed, low
}

const entropyMaxBlocks = 64

// Entropy profiles data. The block size grows so that at most entropyMaxBlocks
// blocks are reported.
func Entropy(data []byte) EntropyProfile {
	p := EntropyProfile{Bits: shannon(data)}
	p.Block = 4096
	for (len(data)+p.Block-1)/p.Block > entropyMaxBlocks {
		p.Block *= 2
	}
	minBlock := 1.0
	for i := 0; i < len(data); i += p.Block {
		blk := data[i:min(i+p.Block, len(data))]
		if len(blk) < p.Block/2 && i > 0 {
			break // a short tail is too small a sample to rate
		}
		b := shannon(blk)
		p.Blocks = append(p.Blocks, b)
		minBlock = math.Min(minBlock, b/8)
	}
	switch {
	case len(data) < 1024:
		p.Class = "low"
	case p.Bits >= 8-255/(float64(len(data))*math.Ln2)-0.05 && minBlock > 0.9:
		// A uniform source of n bytes falls short of 8 bits by about 255/(2n ln 2).
		p.Class = "random"
	case p.Bits > 7.5 && minBlock > 0.8:
		p.Class = "high"
	case p.Bits > 6:
		p.Class = "mixed"
	default:
		p.Class = "low"
	}
	return p
}

func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var count [256]int
	for _, c := range b {
		count[c]++
	}
	h := 0.0
	for _, n := range count {
		if n > 0 {
			p := float64(n) / float64(len(b))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// Describe is the one-line reading of the profile.
func (p EntropyProfile) Describe() string {
	switch p.Class {
	case "random":
		return "indistinguishable from random: encrypted, or compressed with no header"
	case "high":
		return "near-random: compressed or encrypted, with some structure"
	case "mixed":
		return "mixed: structured data with compressed or encrypted regions"
	}
	return "structured"
}

// Spark draws the per-block entropies as one character each.
func (p EntropyProfile) Spark() string {
	const bars = "▁▂▃▄▅▆▇█"
	r := []rune(bars)
	out := make([]rune, len(p.Blocks))
	for i, b := range p.Blocks {
		out[i] = r[min(int(b/8*float64(len(r))), len(r)-1)]
	}
	return string(out)
}

// ByteHistogram counts byte values into 64 bins of four values each: flat for
// ciphertext, lumpy for anything with structure.
func ByteHistogram(data []byte) []int {
	h := make([]int, 64)
	for _, c := range data {
		h[c>>2]++
	}
	return h
}
