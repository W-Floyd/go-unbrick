package main

import (
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

type verEntry = vendor.VerEntry

// verManifest is a .ver of a downloaded firmware collection (see vendor.ParseVer).
type verManifest struct {
	vendor.VerManifest
	Path string
}

func parseVer(path string) (*verManifest, bool) {
	data, err := infile.ReadFile(path)
	if err != nil {
		return nil, false
	}
	m := &verManifest{VerManifest: vendor.ParseVer(data), Path: path}
	return m, len(m.Entries) > 0
}

func fileCRC(path string) (uint32, error) {
	f, err := infile.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	h := crc32.NewIEEE()
	if _, err := io.Copy(h, f); err != nil {
		return 0, err
	}
	return h.Sum32(), nil
}

// reportCollection checks the directory against its manifests and returns the
// files worth recon'ing: each listed file that is present, minus byte-identical
// copies of one already taken (hardlinks, renamed duplicates — the manifest's
// own size and CRC say so without reading anything). Files the manifest does not
// list are kept. CRCs are read only under --verify; they cost a full read.
func reportCollection(dir string, paths []string, verify bool) (keep []string) {
	var manifests []*verManifest
	rest := paths[:0:0]
	for _, p := range paths {
		if strings.EqualFold(filepath.Ext(p), ".ver") {
			if m, ok := parseVer(p); ok {
				manifests = append(manifests, m)
				continue
			}
		}
		rest = append(rest, p)
	}
	if len(manifests) == 0 {
		return paths
	}

	byName := map[string]string{}
	for _, p := range rest {
		byName[filepath.Base(p)] = p
	}
	listed := map[string]bool{}
	type key struct {
		crc  uint32
		size int64
	}
	first := map[key]string{}
	var problems int

	for _, m := range manifests {
		fmt.Printf("Collection: %s", firstNonEmpty(m.Collection, filepath.Base(dir)))
		if m.Build != "" {
			fmt.Printf("  (%s)", m.Build)
		}
		fmt.Printf("\n  Manifest: %s, %d files\n", filepath.Base(m.Path), len(m.Entries))
		for _, e := range m.Entries {
			p, ok := byName[e.Name]
			listed[e.Name] = true
			status, dup := "ok", ""
			switch {
			case !ok:
				status = cBad("missing")
				problems++
			default:
				if fi, err := infile.Stat(p); err != nil || fi.Size() != e.Size {
					status = cBad(fmt.Sprintf("size %d, want %d", fiSize(fi), e.Size))
					problems++
				} else if verify {
					if c, err := fileCRC(p); err != nil || c != e.CRC {
						status = cBad("crc mismatch")
						problems++
					} else {
						status = "ok (crc verified)"
					}
				}
				k := key{e.CRC, e.Size}
				if prev, seen := first[k]; seen {
					dup = prev
				} else {
					first[k] = e.Name
					keep = append(keep, p)
				}
			}
			line := fmt.Sprintf("    %-62s %10s  %s", e.Name, humanBytes(e.Size), status)
			if dup != "" {
				line += "  = " + dup + " (skipped)"
			}
			fmt.Println(line)
		}
	}

	for _, p := range rest {
		if strings.HasSuffix(filepath.Base(p), "TarList.txt_encrypted") {
			reportTarList(p, byName, verify)
		}
	}

	var extra []string
	for _, p := range rest {
		if !listed[filepath.Base(p)] {
			extra = append(extra, p)
			keep = append(keep, p)
		}
	}
	if len(extra) > 0 {
		fmt.Printf("  Not in manifest: %d\n", len(extra))
		for _, p := range extra {
			fmt.Printf("    %s\n", filepath.Base(p))
		}
	}
	if problems > 0 {
		fmt.Printf("  %s %d file(s) missing or damaged; the collection is incomplete\n", cWarn("[!]"), problems)
	}
	fmt.Println()
	return keep
}

func fiSize(fi os.FileInfo) int64 {
	if fi == nil {
		return -1
	}
	return fi.Size()
}

// captureStdout runs fn and returns what it printed.
func captureStdout(fn func() error) (string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	ferr := fn()
	os.Stdout = old
	w.Close()
	return <-done, ferr
}

var memberKind = regexp.MustCompile(`^    \S.*?\s+\[([^\]]+)\]`)

// ansiCode matches one SGR escape sequence (bold, color, reset): the styling
// helpers in cmd_fastboot.go (cHdr et al.) wrap text in these when stdout is a
// terminal, and briefRecon's prefix/regex matching below needs the plain text
// underneath, not the styled line it still writes out unchanged.
var ansiCode = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiCode.ReplaceAllString(s, "") }

// briefRecon keeps a file recon's identity lines and the member count, and
// folds the member listing and everything after it into a kind histogram and a
// warning count. A directory holds dozens of such listings; per-file recon has
// the detail.
func briefRecon(out string) string {
	var b strings.Builder
	kinds := map[string]int{}
	warns := 0
	inList := false
	first := true
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		// runFileRecon's own first line is just the filename, already shown
		// in the caller's "=== name ===" header right above this.
		if first {
			first = false
			continue
		}
		plain := line
		if strings.Contains(plain, "\x1b[") {
			plain = stripANSI(plain)
		}
		switch {
		case strings.HasPrefix(plain, "  Contents ("):
			inList = true
			b.WriteString(line + "\n")
		case inList:
			if strings.Contains(plain, "[encrypted filesystem") || strings.Contains(plain, "ro.build.fingerprint") {
				b.WriteString(line + "\n")
			}
			if strings.Contains(plain, "[encrypted filesystem") {
				kinds["encrypted filesystem"]++
			} else if m := memberKind.FindStringSubmatch(plain); m != nil {
				kinds[m[1]]++
			}
			if strings.Contains(plain, "[!]") {
				warns++
			}
		default:
			b.WriteString(line + "\n")
		}
	}
	if h := histogramLine(kinds); h != "" {
		b.WriteString("    " + h + "\n")
	}
	if warns > 0 {
		fmt.Fprintf(&b, "    %s %d warning(s)\n", cWarn("[!]"), warns)
	}
	return b.String()
}

// histogramLine renders counts by kind, most common first.
func histogramLine(kinds map[string]int) string {
	type kc struct {
		k string
		n int
	}
	var l []kc
	for k, n := range kinds {
		l = append(l, kc{k, n})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].n != l[j].n {
			return l[i].n > l[j].n
		}
		return l[i].k < l[j].k
	})
	var parts []string
	for _, e := range l {
		parts = append(parts, fmt.Sprintf("%s %d", e.k, e.n))
	}
	return strings.Join(parts, ", ")
}

// reportTarList decodes a Hyundai/Kia NEW_TarList.txt_encrypted, printing the
// versions it states. Its per-file hashes (Hyundai's own two-level SHA-224,
// not plain SHA-224 — see vendor.HyundaiSHA224) are checked only under
// --verify, which reads each listed file in full.
func reportTarList(path string, byName map[string]string, verify bool) {
	data, err := infile.ReadFile(path)
	if err != nil {
		return
	}
	data = vendor.DecodeTarList(data)
	var bad []string
	checked := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "@FILE:"):
			f := strings.Split(strings.TrimPrefix(line, "@FILE:"), ",")
			p, ok := byName[f[0]]
			if !verify || len(f) < 3 || !ok {
				continue
			}
			checked++
			if got, err := tarListFileHash(p); err != nil || got != f[2] {
				bad = append(bad, f[0])
			}
		case strings.HasPrefix(line, "@NEW_SWVERSION_K:"), strings.HasPrefix(line, "@NEW_VERSION:"):
			fmt.Printf("  %s\n", strings.Replace(strings.TrimPrefix(line, "@"), ":", ": ", 1))
		}
	}
	if verify {
		if len(bad) > 0 {
			fmt.Printf("  %s TarList hash mismatch: %s\n", cWarn("[!]"), strings.Join(bad, ", "))
		} else {
			fmt.Printf("  TarList hash: %d file(s) verified\n", checked)
		}
	}
}

func tarListFileHash(path string) (string, error) {
	f, err := infile.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return vendor.HyundaiSHA224(f)
}

var (
	partName    = regexp.MustCompile(`^(.+\.tar)(\d+)$`)
	membersLine = regexp.MustCompile(`^  Contents \((\d+) members\)`)
)

// partUnits groups numbered split parts (navi_backup.tar1…9) into one unit;
// every other file is its own. Order follows first appearance.
func partUnits(paths []string) [][]string {
	var units [][]string
	at := map[string]int{}
	for _, p := range paths {
		m := partName.FindStringSubmatch(filepath.Base(p))
		if m == nil {
			units = append(units, []string{p})
			continue
		}
		k := filepath.Join(filepath.Dir(p), m[1])
		if i, ok := at[k]; ok {
			units[i] = append(units[i], p)
			continue
		}
		at[k] = len(units)
		units = append(units, []string{p})
	}
	for _, u := range units {
		sort.Strings(u)
	}
	return units
}

// reconParts reports a set of split parts as one: total size and members, one
// merged kind histogram. Parts are independent tars, so each is read alone.
func reconParts(label string, parts []string) (failed []string) {
	var size int64
	members, warns := 0, 0
	kinds := map[string]int{}
	for _, p := range parts {
		if fi, err := infile.Stat(p); err == nil {
			size += fi.Size()
		}
		out, err := captureStdout(func() error { return runFileRecon(p) })
		if err != nil {
			failed = append(failed, filepath.Base(p))
		}
		for _, line := range strings.Split(out, "\n") {
			plain := line
			if strings.Contains(plain, "\x1b[") {
				plain = stripANSI(plain)
			}
			if m := membersLine.FindStringSubmatch(plain); m != nil {
				n, _ := strconv.Atoi(m[1])
				members += n
			} else if strings.Contains(plain, "[!]") {
				warns++
			} else if m := memberKind.FindStringSubmatch(plain); m != nil && !strings.Contains(plain, "[!]") {
				kinds[m[1]]++
			}
		}
	}
	fmt.Printf("  %d parts, %s, %d members\n", len(parts), humanBytes(size), members)
	if h := histogramLine(kinds); h != "" {
		fmt.Printf("    %s\n", h)
	}
	if warns > 0 {
		fmt.Printf("    %s %d warning(s)\n", cWarn("[!]"), warns)
	}
	return failed
}

// skipGroups name sets of files --skip can leave out of a directory recon.
// Any other --skip value is a glob on the file's base name.
var skipGroups = map[string]func(base string) bool{
	// The split parts (navi_backup.tar1, …) and the whole file (navi_backup.tar).
	"navi": func(base string) bool {
		return base == "navi_backup.tar" || partName.MatchString(base) && strings.HasPrefix(base, "navi_backup.")
	},
}

// skipMatch reports whether one --skip value names the file with this base name.
func skipMatch(skip, base string) bool {
	if f, ok := skipGroups[skip]; ok {
		return f(base)
	}
	ok, _ := filepath.Match(skip, base)
	return ok
}

// applySkips drops the files the --skip values name and reports what it left out.
func applySkips(paths, skips []string) []string {
	if len(skips) == 0 {
		return paths
	}
	var keep []string
	dropped := map[string][]string{}
	for _, p := range paths {
		base := filepath.Base(p)
		hit := ""
		for _, s := range skips {
			if skipMatch(s, base) {
				hit = s
				break
			}
		}
		if hit == "" {
			keep = append(keep, p)
		} else {
			dropped[hit] = append(dropped[hit], p)
		}
	}
	for _, s := range skips {
		if ps := dropped[s]; len(ps) > 0 {
			var size int64
			for _, p := range ps {
				if fi, err := infile.Stat(p); err == nil {
					size += fi.Size()
				}
			}
			fmt.Printf("Skipped %s: %d file(s), %s\n", s, len(ps), humanBytes(size))
		}
	}
	return keep
}
