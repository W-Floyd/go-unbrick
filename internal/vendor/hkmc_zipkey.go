package vendor

import (
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
)

// ZipPassworder is an optional Driver capability: how this OEM's packages derive
// the passwords of the encrypted zips inside them. The zip is the container the
// encrypted member is in; its place in the tree (carve.Node.Parent) is what a
// package's password is derived from.
type ZipPassworder interface {
	ZipPasswords(zip *carve.Node, member string) []string
}

// ZipPasswords gathers every registered driver's candidate passwords for an
// encrypted member of zip: what carve.ZipPasswords is set to.
func ZipPasswords(zip *carve.Node, member string) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range Drivers() {
		if z, ok := d.(ZipPassworder); ok {
			for _, p := range z.ZipPasswords(zip, member) {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// A taxi/fleet head-unit package ("MS400A_KIA_202601071722_<name>.zip") holds an
// UpdateFiles/ with an inventory (fwinfo.ini) and an encapsuled.zip, whose one
// member is an Android OTA zip encrypted with the traditional zip cipher. The
// password is the package's date, yymmdd: the century dropped from the yyyymmdd of
// its build timestamp. The date is in the package three times, and any one will do:
//
//   - fwinfo.ini: "CPU.timestamp = 202601071722" (yyyymmddhhmm);
//   - the package's file name: MS400A_KIA_202601071722_...;
//   - the date the outer zip records for its entries.
//
// All are tried, the inventory's first.
var (
	// stampRE is a yyyymmdd (with a time after it or not) between non-digits.
	stampRE   = regexp.MustCompile(`(?:^|\D)(20\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?:\d{4})?(?:\D|$)`)
	fwStampRE = regexp.MustCompile(`(?im)^\s*[\w.]*timestamp\s*=\s*(\d+)`)
)

// ZipPasswords implements ZipPassworder.
func (hkmc) ZipPasswords(zn *carve.Node, member string) []string {
	var inventory, names, entries []string
	for n := zn; n != nil; n = n.Parent() {
		names = append(names, stampsIn(path.Base(strings.TrimSuffix(n.Name, "/")))...)
		if !n.Modified.IsZero() {
			entries = append(entries, n.Modified.UTC().Format("060102"))
		}
		p := n.Parent()
		if p == nil {
			continue
		}
		// The package's inventory sits beside the zip, among its siblings.
		_, sibs, _ := p.Children()
		for _, s := range sibs {
			if !s.Modified.IsZero() {
				entries = append(entries, s.Modified.UTC().Format("060102"))
			}
			if strings.EqualFold(path.Base(s.Name), "fwinfo.ini") && path.Dir(s.Name) == path.Dir(n.Name) {
				inventory = append(inventory, fwinfoStamps(s)...)
			}
		}
	}
	return dedupe(inventory, names, entries)
}

// stampsIn is the yymmdd of every date in a string.
func stampsIn(s string) []string {
	var out []string
	for _, m := range stampRE.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1][2:]+m[2]+m[3])
	}
	return out
}

// fwinfoStamps reads the timestamps of an inventory file.
func fwinfoStamps(n *carve.Node) []string {
	rc, err := n.Reader()
	if err != nil {
		return nil
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, 64<<10))
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range fwStampRE.FindAllStringSubmatch(string(data), -1) {
		out = append(out, stampsIn(m[1])...)
	}
	return out
}

func dedupe(lists ...[]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range lists {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}
