package telechips

import (
	"regexp"
	"strings"
)

// LKSource is what an LK bootloader source tree states about the build: its
// project makefile (target and the defines it turns on) and the target's rules
// (platform, board revision).
type LKSource struct {
	Target   string   // TARGET :=
	Platform string   // PLATFORM := from the target's rules.mk
	HWRev    string   // HW_REV=, e.g. "0x4210"
	Board    string   // what the rules.mk comment says that revision is
	Flags    []string // defines and switches active after evaluating the conditionals, in order
}

var (
	assignRe = regexp.MustCompile(`^([A-Za-z0-9_]+)\s*(:=|\?=|\+=|=)\s*(.*?)\s*$`)
	condRe   = regexp.MustCompile(`^(ifeq|ifneq)\s*\(\s*\$\((\w+)\)\s*,\s*([^)]*?)\s*\)$`)
	defRe    = regexp.MustCompile(`^(ifdef|ifndef)\s+(\w+)$`)
	hwRevRe  = regexp.MustCompile(`(?m)^\s*HW_REV\s*=\s*(0x[0-9a-fA-F]+)`)
	revNote  = regexp.MustCompile(`(?m)^#\s*(0x[0-9a-fA-F]+)\s*:\s*(.+?)\s*$`)
)

// evalMakefile reads the plain subset of make a project file uses: variable
// assignments and ifeq/ifneq/ifdef/ifndef blocks over them. It returns the
// variables and the DEFINES that are in effect.
func evalMakefile(data []byte) (vars map[string]string, defines []string) {
	vars = map[string]string{}
	type frame struct{ taking, parent, done bool }
	var stack []frame
	active := func() bool { return len(stack) == 0 || stack[len(stack)-1].taking }
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "endif"):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		case line == "else" || strings.HasPrefix(line, "else "):
			if n := len(stack); n > 0 {
				f := &stack[n-1]
				f.taking = f.parent && !f.done
			}
			continue
		}
		var cond bool
		isCond := false
		if m := condRe.FindStringSubmatch(line); m != nil {
			isCond, cond = true, (vars[m[2]] == strings.Trim(m[3], `"'`)) == (m[1] == "ifeq")
		} else if m := defRe.FindStringSubmatch(line); m != nil {
			_, set := vars[m[2]]
			isCond, cond = true, set == (m[1] == "ifdef")
		} else if strings.HasPrefix(line, "if") {
			isCond = true // a conditional this does not model: skip its branches
		}
		if isCond {
			parent := active()
			stack = append(stack, frame{taking: parent && cond, parent: parent, done: parent && cond})
			continue
		}
		if !active() {
			continue
		}
		m := assignRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, op, val := m[1], m[2], m[3]
		switch {
		case name == "DEFINES" && op == "+=":
			for _, d := range strings.Fields(val) {
				defines = append(defines, strings.TrimPrefix(d, "-D"))
			}
		case op == "?=":
			if _, ok := vars[name]; !ok {
				vars[name] = val
			}
		case op == "+=":
			vars[name] = strings.TrimSpace(vars[name] + " " + val)
		default:
			vars[name] = val
		}
	}
	return vars, defines
}

// ParseLKSource reads an LK project makefile and, if given, its target's rules.mk.
// ok is false when project has no TARGET.
func ParseLKSource(project, rules []byte) (LKSource, bool) {
	vars, defines := evalMakefile(project)
	s := LKSource{Target: vars["TARGET"]}
	if s.Target == "" {
		return s, false
	}
	// Switches the project sets to 1 and the defines it adds are the build's flags.
	for _, d := range defines {
		s.Flags = append(s.Flags, d)
	}
	seen := map[string]bool{}
	for _, d := range s.Flags {
		seen[strings.SplitN(d, "=", 2)[0]] = true
	}
	for _, k := range []string{"DEBUG", "EMMC_BOOT", "NAND_BOOT", "TZOW_ENABLE", "TSBM_INCLUDE", "TCC_NSK_ENABLE", "HIDDEN_ENABLE", "GPHD_ENABLE"} {
		if vars[k] == "1" && !seen[k] {
			s.Flags = append(s.Flags, k+"=1")
		}
	}
	if rules != nil {
		rv, _ := evalMakefile(rules)
		s.Platform = rv["PLATFORM"]
		if m := hwRevRe.FindSubmatch(rules); m != nil {
			s.HWRev = string(m[1])
			for _, n := range revNote.FindAllSubmatch(rules, -1) {
				if strings.EqualFold(string(n[1]), s.HWRev) {
					s.Board = string(n[2])
				}
			}
		}
	}
	return s, true
}

// flagWords says in words the flags that describe how the bootloader behaves, in
// the order they are reported; a flag not listed is left out rather than guessed at.
var flagWords = []struct {
	words string
	flags []string
}{
	{"debug build", []string{"DEBUG"}},
	{"UART debug output", []string{"WITH_DEBUG_UART"}},
	{"framebuffer console", []string{"WITH_DEBUG_FBCON"}},
	{"debug log buffer", []string{"WITH_DEBUG_LOG_BUF"}},
	{"device tree", []string{"DEVICE_TREE"}},
	{"eMMC boot", []string{"EMMC_BOOT", "_EMMC_BOOT"}},
	{"NAND boot", []string{"NAND_BOOT", "_NAND_BOOT"}},
	{"Telechips secure boot manager", []string{"TSBM_ENABLE"}},
	{"TrustZone OW", []string{"TZOW_ENABLE"}},
	{"Telechips NSK", []string{"TCC_NSK_ENABLE"}},
	{"kernel panic capture", []string{"TCC_KPANIC"}},
	{"reads data from the MICOM", []string{"MOBIS_GET_DATA_FROM_MICOM"}},
}

// Describe is the build's flags in words.
func (s LKSource) Describe() []string {
	have := map[string]bool{}
	for _, f := range s.Flags {
		have[strings.SplitN(f, "=", 2)[0]] = true
	}
	var out []string
	for _, fw := range flagWords {
		for _, f := range fw.flags {
			if have[f] {
				out = append(out, fw.words)
				break
			}
		}
	}
	return out
}
