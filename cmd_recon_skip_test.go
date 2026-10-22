package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

func TestDefaultSkipIsTheNaviBackups(t *testing.T) {
	for path, want := range map[string]bool{
		"navi_backup.tar": true, "navi_backup.tar1": true, "navi_backup.tar12": true,
		"data/navi_backup.tar3": true, "navi_backup.txt": false, "other.tar1": false,
		"xnavi_backup.tar": false, "navi_backup.tar.bak": false,
	} {
		if got := analysis.SkipPath([]string{defaultSkip}, path); got != want {
			t.Errorf("default skip on %q = %v, want %v", path, got, want)
		}
	}
}

func TestCheckSkips(t *testing.T) {
	got, err := checkSkips([]string{"", `a/b`, ""})
	if err != nil || len(got) != 1 || got[0] != `a/b` {
		t.Errorf("empty patterns are dropped: %v %v", got, err)
	}
	if _, err := checkSkips([]string{`(`}); err == nil {
		t.Error("an invalid regular expression was accepted")
	}
}

func TestApplySkipsMatchesThePathFromTheDirectory(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"navi_backup.tar1", "sw_backup.tar", "sub/keep.bin", "sub/drop.log"} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	kept := applySkips(dir, paths, []string{defaultSkip, `^sub/.*\.log$`})
	if len(kept) != 2 || filepath.Base(kept[0]) != "sw_backup.tar" || filepath.Base(kept[1]) != "keep.bin" {
		t.Errorf("kept %v", kept)
	}
}
