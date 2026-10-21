package vendor

import (
	"reflect"
	"testing"
)

func TestParseNotice(t *testing.T) {
	in := "/*\n * File path1 : a.c\n * File path2 : b.c\n * License Name : GNU General Public License v2.0 or later\n */\n/*\n * File path : c.c\n * License Name : MIT\n */\n"
	got := ParseNotice([]byte(in))
	if got.Files != 3 || !reflect.DeepEqual(got.Licenses, []string{"GNU General Public License v2.0 or later", "MIT"}) {
		t.Errorf("got %+v", got)
	}
	if s := ParseNotice([]byte("### notice ###\nalsa-lib (LGPL-2.1)")); s.Files != 0 || len(s.Licenses) != 0 {
		t.Errorf("package list: %+v", s)
	}
}

func TestSourceRelease(t *testing.T) {
	names := map[string]bool{
		"ccNC_a/x.c": true, "ccNC_a/d/y.c": true, "ccNC_b/z.c": true,
		"ccNC_a_notice.txt": true, "readme.txt": true,
	}
	comps, notices := sourceRelease(names)
	if !reflect.DeepEqual(comps, []string{"ccNC_a (2 files)", "ccNC_b (1 files)"}) || !reflect.DeepEqual(notices, []string{"ccNC_a_notice.txt"}) {
		t.Errorf("%v %v", comps, notices)
	}
}
