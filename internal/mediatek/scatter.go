// Package mediatek derives the MediaTek SoC ("chip", e.g. MT6765) and partition
// layout from an SP Flash Tool package's scatter file — the MediaTek analog of a
// Qualcomm blankflash's cpu.name. The scatter is YAML: a "general" block naming
// the platform, then one entry per partition. This is identification only; MTK
// flashing (BROM/Download Agent) is a separate transport not implemented here.
package mediatek

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	yaml "go.yaml.in/yaml/v4"
)

type Partition struct {
	Name     string
	FileName string
	Region   string
	Type     string
	Download bool
}

// Info is the derived MediaTek identity of a package.
type Info struct {
	Chip       string // SoC, e.g. "MT6765" (from the scatter's platform field or name)
	Project    string // vendor project, e.g. "k65v1_64_bsp"
	Storage    string // EMMC / UFS
	Partitions []Partition
	Source     string // where the scatter was found
}

var reChip = regexp.MustCompile(`(?i)MT\d{4}`)

// ParseScatter derives the chip and partitions from scatter bytes. Two dialects
// exist: older scatters list partitions at the top level; newer ones nest them
// under a storage_type item's "description" list — so the walk recurses. nameHint
// (the scatter filename) is a fallback for the chip when no platform field parses.
func ParseScatter(b []byte, nameHint string) (*Info, error) {
	var items []map[string]any
	if err := yaml.Unmarshal(b, &items); err != nil {
		return nil, fmt.Errorf("scatter is not valid YAML: %w", err)
	}
	info := &Info{}
	var walk func(list []map[string]any)
	walk = func(list []map[string]any) {
		for _, it := range list {
			if _, ok := it["general"]; ok {
				if inf := firstMap(it["info"]); inf != nil {
					if p := str(inf["platform"]); p != "" {
						info.Chip = strings.ToUpper(p)
					}
					if pr := str(inf["project"]); pr != "" {
						info.Project = pr
					}
					if s := str(inf["storage"]); s != "" && info.Storage == "" {
						info.Storage = s
					}
				}
			}
			if st := str(it["storage_type"]); st != "" && info.Storage == "" {
				info.Storage = st
			}
			if desc, ok := it["description"]; ok {
				walk(mapList(desc)) // newer dialect: partitions nested here
			}
			if pn := str(it["partition_name"]); pn != "" {
				info.Partitions = append(info.Partitions, Partition{
					Name: pn, FileName: str(it["file_name"]),
					Region: str(it["region"]), Type: str(it["type"]),
					Download: str(it["is_download"]) == "true",
				})
			}
		}
	}
	walk(items)
	if info.Chip == "" {
		info.Chip = strings.ToUpper(reChip.FindString(nameHint))
	}
	if info.Chip == "" {
		return nil, fmt.Errorf("no MediaTek chip found in scatter (platform field and name both empty)")
	}
	return info, nil
}

// str coerces a decoded YAML scalar to a trimmed string.
func str(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", x))
	}
}

// asMap normalizes either map form the YAML decoder may produce.
func asMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprintf("%v", k)] = val
		}
		return out
	}
	return nil
}

func firstMap(v any) map[string]any {
	if l, ok := v.([]any); ok {
		for _, e := range l {
			if m := asMap(e); m != nil {
				return m
			}
		}
	}
	return nil
}

func mapList(v any) []map[string]any {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(l))
	for _, e := range l {
		if m := asMap(e); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func isScatter(name string) bool {
	l := strings.ToLower(filepath.Base(name))
	return strings.Contains(l, "scatter") && strings.HasSuffix(l, ".txt")
}

// FromPackage locates the scatter in a directory, zip, or a scatter file itself
// and derives the MediaTek identity.
func FromPackage(path string) (*Info, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		var found string
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && isScatter(p) && found == "" {
				found = p
			}
			return nil
		})
		if found == "" {
			return nil, fmt.Errorf("no scatter file under %s", path)
		}
		b, err := os.ReadFile(found)
		if err != nil {
			return nil, err
		}
		info, err := ParseScatter(b, found)
		if info != nil {
			info.Source = found
		}
		return info, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		zr, err := zip.OpenReader(path)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		for _, f := range zr.File {
			if !isScatter(f.Name) {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
			info, err := ParseScatter(b, f.Name)
			if info != nil {
				info.Source = path + "!" + f.Name
			}
			return info, err
		}
		return nil, fmt.Errorf("no scatter file in %s", path)
	}
	// A scatter file directly.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	info, err := ParseScatter(b, path)
	if info != nil {
		info.Source = path
	}
	return info, err
}
