package main

import "testing"

func TestNaviGroup(t *testing.T) {
	for name, want := range map[string]bool{
		"navi_backup.tar": true, "navi_backup.tar1": true, "navi_backup.tar12": true,
		"navi_backup.txt": false, "other.tar1": false, "xnavi_backup.tar": false,
	} {
		if got := skipMatch("navi", name); got != want {
			t.Errorf("navi on %q = %v, want %v", name, got, want)
		}
	}
}
