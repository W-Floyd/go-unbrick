package main

import (
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// diffTrust says to take a vendor manifest's word for a file's identity rather
// than reading the file; --verify turns it off.
var diffTrust = true

// maxManifestRead bounds a member read as a manifest candidate.
const maxManifestRead = 8 << 20

// claimSet is every hash stated for each path. One file is often named by
// several manifests in different algorithms (a .ver's CRC32, an update.info's
// SHA-224), so a path holds them all, not whichever was read last.
type claimSet map[string][]vendor.FileClaim

// algoRank orders algorithms strongest first, so the same file always yields
// its claims in the same order, whichever manifest was read first.
func algoRank(a string) int {
	switch a {
	case "sha256":
		return 0
	case "hyundai-sha224":
		return 1
	case "crc32":
		return 3
	}
	return 2
}

func sortClaims(cs []vendor.FileClaim) {
	sort.SliceStable(cs, func(i, j int) bool {
		if ri, rj := algoRank(cs[i].Algo), algoRank(cs[j].Algo); ri != rj {
			return ri < rj
		}
		return cs[i].Algo < cs[j].Algo
	})
}

// manifestClaims is what the vendors' manifests among root's top-level members
// say about its files, by path from root.
func manifestClaims(root *carve.Node) claimSet {
	_, kids, err := root.Children()
	if err != nil {
		return nil
	}
	byName := map[string]*carve.Node{}
	pkg := vendor.PackageAccess{Names: map[string]bool{}}
	for _, k := range kids {
		byName[k.Name] = k
		pkg.Names[k.Name] = true
	}
	pkg.Read = func(name string) []byte {
		k := byName[name]
		if k == nil || k.IsDirNode() || k.Size > maxManifestRead {
			return nil
		}
		b, _ := k.Bytes()
		return b
	}
	claims := claimSet{}
	for _, c := range vendor.Manifests(pkg) {
		claims[c.Path] = append(claims[c.Path], c)
	}
	for _, cs := range claims {
		sortClaims(cs)
	}
	return claims
}

// claimsFor is every claim about the member at path that can be trusted
// against what is cheaply known of the member itself (a claimed size that
// disagrees with the member's means the manifest is not describing it),
// strongest algorithm first. A member's own container may add one a manifest
// did not give: a zip's CRC32, an OTA's partition SHA-256.
func claimsFor(claims claimSet, path string, n *carve.Node) []vendor.FileClaim {
	var out []vendor.FileClaim
	have := map[string]bool{}
	for _, c := range claims[path] {
		if c.Sum != "" && !(c.Size >= 0 && n.Size >= 0 && c.Size != n.Size) {
			out = append(out, c)
			have[c.Algo] = true
		}
	}
	if nc := n.Claim(); nc != nil && !have[nc.Algo] && nc.Sum != "" && !(nc.Size >= 0 && n.Size >= 0 && nc.Size != n.Size) {
		out = append(out, vendor.FileClaim{Path: path, Size: nc.Size, Algo: nc.Algo, Sum: nc.Sum})
		sortClaims(out)
	}
	return out
}

// claimFor is the best claim about the member at path, if any.
func claimFor(claims claimSet, path string, n *carve.Node) (vendor.FileClaim, bool) {
	if cs := claimsFor(claims, path, n); len(cs) > 0 {
		return cs[0], true
	}
	return vendor.FileClaim{}, false
}

// commonClaims compares two sets of claims on every algorithm both give.
// settled is false when they share none, which settles nothing; otherwise equal
// says whether every shared algorithm agrees, so one that differs is enough
// to show the bytes do.
func commonClaims(xs, ys []vendor.FileClaim) (settled, equal bool) {
	equal = true
	for _, a := range xs {
		for _, b := range ys {
			if a.Algo == b.Algo {
				settled = true
				if a.Sum != b.Sum {
					equal = false
				}
			}
		}
	}
	return settled, settled && equal
}

// subClaims is the manifest claims among n's top-level members, keyed under
// prefix so they match the paths a comparison of n's members builds. A
// container's own manifest (an update.info inside a tar) is as good a source as
// one beside the package, and the only one for what is nested.
func subClaims(n *carve.Node, prefix string) claimSet {
	if !diffTrust {
		return nil
	}
	m := manifestClaims(n)
	if prefix == "" || len(m) == 0 {
		return m
	}
	out := make(claimSet, len(m))
	for k, cs := range m {
		out[prefix+k] = cs
	}
	return out
}

// algoList names the algorithms of cs, for the profile log.
func algoList(cs []vendor.FileClaim) string {
	if len(cs) == 0 {
		return "none"
	}
	var out []string
	for _, c := range cs {
		out = append(out, c.Algo)
	}
	return strings.Join(out, ",")
}
