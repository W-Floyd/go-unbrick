package gitlog

import (
	"strings"
	"testing"
)

const sample = "\x1b[33mcommit 8baf023fb52824aaa33c3ef59c3bd580cb871342\x1b[m\n" +
	"Author: YongSeoK Oh <ysoh4011@telechips.com>\n" +
	"Date:   Tue Jun 28 12:24:45 2016 +0900\n\n" +
	"    [updatep] TCC897X SRAM Boot Code update\n\n" +
	"\x1b[33mcommit b846f5a752d154f141c7be93e1c31d4bf6cc0ba4\x1b[m (HEAD -> x)\n" +
	"Author: Roger Quadros <rogerq@ti.com>\n" +
	"Date:   Thu Jun 23 11:34:20 2016 +0900\n\n" +
	"    usb: fix\n    \n    body line that must not become the subject\n\n" +
	"commit fa85e826c16b8f4a5b4d0b6f0b3e9e0c6a0e1d11\n" +
	"Author: Tom Rini <trini@konsulko.com>\n" +
	"Date:   Tue Jan 12 09:06:54 2016 -0500\n\n" +
	"    Prepare v2016.01\n\n" +
	"commit 84b5e8022ef62b68df360392a55c4fc2f2e568d7\n" +
	"Merge: aaa bbb\n" +
	"Author: Wolfgang Denk <wd@denx.de>\n" +
	"Date:   2011-07-29 14:42:18 +0200\n\n" +
	"    Constify getenv()\n"

func TestParse(t *testing.T) {
	l, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Commits) != 4 {
		t.Fatalf("%d commits", len(l.Commits))
	}
	c := l.Commits[0]
	if c.Hash != "8baf023fb52824aaa33c3ef59c3bd580cb871342" || c.Author != "YongSeoK Oh" || c.Email != "ysoh4011@telechips.com" ||
		c.Subject != "[updatep] TCC897X SRAM Boot Code update" || c.Date.Year() != 2016 || c.Merge {
		t.Errorf("first commit: %+v", c)
	}
	if l.Commits[1].Subject != "usb: fix" {
		t.Errorf("subject %q", l.Commits[1].Subject)
	}
	if last := l.Commits[3]; !last.Merge || last.Date.Year() != 2011 || last.Date.Month() != 7 {
		t.Errorf("iso date / merge: %+v", last)
	}
}

func TestBaseAndSpan(t *testing.T) {
	l, _ := Parse(strings.NewReader(sample))
	i, ok := l.Base()
	if !ok || i != 2 || l.Commits[i].Hash[:8] != "fa85e826" {
		t.Fatalf("base %d %v", i, ok)
	}
	above := l.Commits[:i]
	oldest, newest := Span(above)
	if oldest.Day() != 23 || newest.Day() != 28 || Authors(above) != 2 {
		t.Errorf("span %v %v authors %d", oldest, newest, Authors(above))
	}
	if Domain("a@Telechips.com") != "telechips.com" || Domain("nope") != "" {
		t.Error("domain")
	}
}

func TestLooksLike(t *testing.T) {
	if !LooksLike([]byte(sample)) {
		t.Error("a log was not recognised")
	}
	for _, not := range []string{"", "commit message goes here\nAuthor: x\n", "#!/bin/sh\necho hi\n", "/* File path : a.c */\n"} {
		if LooksLike([]byte(not)) {
			t.Errorf("recognised %q", not)
		}
	}
}
