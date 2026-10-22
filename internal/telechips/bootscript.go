package telechips

import (
	"regexp"
	"strings"
)

// PartitionLoad is one partition a U-Boot boot script reads into memory.
type PartitionLoad struct {
	Partition string
	Command   string // what reads it: "fdt load", "tcc_load part", "dtimg load", "boot_android"
	// BeforeAVB says it is read ahead of the script's `avb verify` step, so what
	// consumes it (a core it starts, a device tree it applies) does so before
	// verification has run.
	BeforeAVB bool
}

var (
	runRE       = regexp.MustCompile(`\brun\s+([A-Za-z0-9_]+)`)
	varRE       = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)
	partitionRE = regexp.MustCompile(`#(\$\{[A-Za-z0-9_]+\}|[A-Za-z0-9_]+)`)
)

// expandScript inlines `run name` and ${name} from env, as far as env defines them.
// What it does not define (${slot}, ${bootdevnum}: known only at run time) stays.
func expandScript(s string, env map[string]string) string {
	for pass := 0; pass < 5; pass++ {
		before := s
		s = runRE.ReplaceAllStringFunc(s, func(m string) string {
			if v, ok := env[runRE.FindStringSubmatch(m)[1]]; ok {
				return v
			}
			return m
		})
		s = varRE.ReplaceAllStringFunc(s, func(m string) string {
			if v, ok := env[varRE.FindStringSubmatch(m)[1]]; ok {
				return v
			}
			return m
		})
		if s == before {
			break
		}
	}
	return s
}

// shellKeywords begin a statement of a script's conditionals, which are not part of
// the command.
var shellKeywords = []string{"if ", "then ", "else ", "elif "}

// BootLoads reads which partitions a stage's default `bootcmd` loads, in order, and
// whether it runs an `avb verify` step. Commands that read the A/B or boot-control
// data (`ab select`, `bcb load`) are not loads of an image. boot_android names the
// partition holding its control data (misc) but boots the boot partition, which is
// what it is reported as.
func BootLoads(env map[string]string) (loads []PartitionLoad, verifies bool) {
	script := expandScript(env["bootcmd"], env)
	verifyAt := -1
	var stmts []string
	for _, raw := range strings.Split(script, ";") {
		s := strings.TrimSpace(raw)
		for changed := true; changed; {
			changed = false
			for _, k := range shellKeywords {
				if strings.HasPrefix(s, k) {
					s, changed = strings.TrimSpace(strings.TrimPrefix(s, k)), true
				}
			}
		}
		if s != "" && s != "fi" {
			stmts = append(stmts, s)
		}
	}
	for i, s := range stmts {
		if verifyAt < 0 && strings.Contains(s, "avb verify") {
			verifyAt = i
		}
	}
	seen := map[string]bool{}
	for i, s := range stmts {
		m := partitionRE.FindStringSubmatch(s)
		if m == nil || strings.HasPrefix(s, "ab ") || strings.HasPrefix(s, "bcb ") {
			continue
		}
		part := m[1]
		var cmd []string
		for _, w := range strings.Fields(s[:strings.Index(s, "#")]) {
			if w != "-" && !strings.ContainsAny(w, "#$") && len(cmd) < 2 {
				cmd = append(cmd, w)
			}
		}
		command := strings.Join(cmd, " ")
		if strings.HasPrefix(command, "boot_android") {
			command = "boot_android"
			part = env["bootpart"]
			if part == "" {
				part = "boot"
			}
		}
		if seen[part] {
			continue
		}
		seen[part] = true
		loads = append(loads, PartitionLoad{Partition: part, Command: command, BeforeAVB: verifyAt >= 0 && i < verifyAt})
	}
	return loads, verifyAt >= 0
}
