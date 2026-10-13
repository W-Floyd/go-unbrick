package port

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// CheckResult is what compiling a generated board dts against a kernel tree
// says.
type CheckResult struct {
	Errors         []string // dtc errors in the board build
	BaselineErrors int      // errors the bare SoC dtsi has by itself (labels it leaves to the board)
	Unresolved     []string // of those, the ones the board still has: it does not compile yet
	Added          []string // warnings the board adds over the bare SoC dtsi
}

var stdinPos = regexp.MustCompile(`<stdin>:[0-9.\-]+: `)

// CheckDTS preprocesses and compiles the board dts with the C preprocessor and
// dtc, the way the kernel build does, and compares with a build of the SoC dtsi
// alone, so the warnings the SoC file has on its own are not blamed on the
// board. It needs a C preprocessor (clang, gcc or cpp) and dtc on PATH.
func CheckDTS(tree, dtsPath, socFile string) (CheckResult, error) {
	var pp []string
	for _, c := range []string{"clang", "gcc", "cc"} {
		if p, err := exec.LookPath(c); err == nil {
			pp = []string{p, "-E"}
			break
		}
	}
	if pp == nil {
		return CheckResult{}, fmt.Errorf("no C preprocessor (clang, gcc or cc) on PATH")
	}
	dtc, err := exec.LookPath("dtc")
	if err != nil {
		return CheckResult{}, fmt.Errorf("dtc is not on PATH")
	}
	soc := filepath.ToSlash(socFile)
	vendorDir := filepath.Join(tree, filepath.Dir(filepath.FromSlash(soc)))

	build := func(file string) (string, error) {
		args := append(pp[1:], "-nostdinc", "-undef", "-x", "assembler-with-cpp", "-P", "-D__DTS__",
			"-I", filepath.Join(tree, "include"), "-I", filepath.Join(tree, "arch", "arm64", "boot", "dts"),
			"-I", vendorDir, "-I", filepath.Dir(dtsPath), file)
		var src, errs bytes.Buffer
		cmd := exec.Command(pp[0], args...)
		cmd.Stdout, cmd.Stderr = &src, &errs
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("preprocessing %s: %v: %s", filepath.Base(file), err, firstLines(errs.String(), 3))
		}
		var out bytes.Buffer
		d := exec.Command(dtc, "-I", "dts", "-O", "dtb", "-@", "-W", "no-unit_address_vs_reg", "-o", os.DevNull, "-")
		d.Stdin, d.Stdout, d.Stderr = &src, &out, &out
		d.Run() // dtc's exit status is its verdict; its messages are what we read
		return out.String(), nil
	}

	tmp, err := os.MkdirTemp("", "unbrick-dtcheck-")
	if err != nil {
		return CheckResult{}, err
	}
	defer os.RemoveAll(tmp)
	stub := filepath.Join(tmp, "soc.dts")
	if err := os.WriteFile(stub, []byte("/dts-v1/;\n#include \""+filepath.Base(soc)+"\"\n"), 0o644); err != nil {
		return CheckResult{}, err
	}
	base, err := build(stub)
	if err != nil {
		return CheckResult{}, err
	}
	full, err := build(dtsPath)
	if err != nil {
		return CheckResult{}, err
	}

	norm := func(s string) map[string]bool {
		out := map[string]bool{}
		for _, l := range strings.Split(s, "\n") {
			if l = strings.TrimSpace(stdinPos.ReplaceAllString(l, "")); l != "" && !strings.HasPrefix(l, "also defined") {
				out[l] = true
			}
		}
		return out
	}
	isErr := func(l string) bool {
		return strings.Contains(l, "ERROR") || strings.HasPrefix(l, "Error") || strings.Contains(l, "FATAL")
	}
	var r CheckResult
	baseSet := norm(base)
	for l := range baseSet {
		if isErr(l) {
			r.BaselineErrors++
		}
	}
	for l := range norm(full) {
		switch {
		case baseSet[l]:
			if isErr(l) {
				r.Unresolved = append(r.Unresolved, l)
			}
		case isErr(l):
			r.Errors = append(r.Errors, l)
		default:
			r.Added = append(r.Added, l)
		}
	}
	sort.Strings(r.Errors)
	sort.Strings(r.Unresolved)
	sort.Strings(r.Added)
	return r, nil
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "; ")
}

// Summary is the result as lines for the person running the tool.
func (r CheckResult) Summary() []string {
	var out []string
	switch {
	case len(r.Errors) > 0:
		out = append(out, fmt.Sprintf("dts check: the board adds %d errors over the SoC dtsi", len(r.Errors)))
		for _, e := range firstN(r.Errors, 6) {
			out = append(out, "  "+e)
		}
	default:
		out = append(out, fmt.Sprintf("dts check: the board adds no errors over the SoC dtsi, and %d warnings", len(r.Added)))
	}
	switch {
	case len(r.Unresolved) > 0:
		out = append(out, fmt.Sprintf("dts check: the board does not compile yet: %d of the SoC dtsi's %d errors (labels it leaves to the board) remain", len(r.Unresolved), r.BaselineErrors))
		for _, e := range firstN(r.Unresolved, 4) {
			out = append(out, "  "+e)
		}
	case r.BaselineErrors > 0:
		out = append(out, fmt.Sprintf("dts check: the board resolves all %d errors the SoC dtsi has alone (labels it leaves to the board)", r.BaselineErrors))
	}
	for _, w := range firstN(r.Added, 4) {
		out = append(out, "  "+w)
	}
	return out
}
