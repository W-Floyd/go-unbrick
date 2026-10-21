package vendor

import (
	"reflect"
	"testing"
)

func TestParseNotice(t *testing.T) {
	in := "/*\n * File path1 : a.c\n * File path2 : b.c\n * License Name : GNU General Public License v2.0 or later\n * Modification Information & date : kernel config, 2022.05.23\n */\n/*\n * File path : c.c\n * License Name : MIT\n */\n"
	got := ParseNotice([]byte(in))
	if got.Files != 3 || !reflect.DeepEqual(got.Licenses, []string{"GNU General Public License v2.0 or later", "MIT"}) {
		t.Errorf("got %+v", got)
	}
	if len(got.Mods) != 1 || got.Mods[0].Date != "2022-05-23" || got.Mods[0].Title != "kernel config" {
		t.Errorf("mods %+v", got.Mods)
	}
	if s := ParseNotice([]byte("### notice ###\nalsa-lib (LGPL-2.1)")); s.Files != 0 || len(s.Licenses) != 0 || len(s.Mods) != 0 {
		t.Errorf("package list: %+v", s)
	}
}

func TestParseNoticeModificationBlocks(t *testing.T) {
	in := ` * License Name : GNU General Public License v2.0 or later

====================
Modification: [WIDE][BSP][X-1] add check_rsa_image driver at uboot
Date: 2020-12-28

u-boot/common/cmd_usb.c
u-boot/drivers/mobis/verify_update_image.c
====================
Modification: Initialize uboot
Date: 2017-10
`
	s := ParseNotice([]byte(in))
	if len(s.Mods) != 2 {
		t.Fatalf("%+v", s.Mods)
	}
	if m := s.Mods[0]; m.Date != "2020-12-28" || len(m.Files) != 2 || m.Files[1] != "u-boot/drivers/mobis/verify_update_image.c" {
		t.Errorf("mod0 %+v", m)
	}
	if first, last := s.Span(); first != "2017-10" || last != "2020-12-28" {
		t.Errorf("span %q %q", first, last)
	}
	if !security.MatchString(s.Mods[0].Title) || security.MatchString(s.Mods[1].Title) {
		t.Error("security filter")
	}
}

func TestNormDate(t *testing.T) {
	for in, want := range map[string]string{
		"2022.05.23": "2022-05-23", "2023. 07. 20": "2023-07-20", "28/11/2024": "2024-11-28",
		"Optimized bit-packing, 28/11/2024": "2024-11-28", "2017-10": "2017-10", "none": "",
	} {
		if got := normDate(in); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

func TestSourceRelease(t *testing.T) {
	names := map[string]bool{
		"ccNC_a/x.c": true, "ccNC_a/d/y.c": true, "ccNC_b/z.c": true,
		"ccNC_a_notice.txt": true, "0109_AVNT5W_kernellk_x.txt": true, "readme.txt": true,
	}
	comps, notices, _ := sourceRelease(names)
	if !reflect.DeepEqual(comps, []string{"ccNC_a (2 files)", "ccNC_b (1 files)"}) ||
		!reflect.DeepEqual(notices, []string{"0109_AVNT5W_kernellk_x.txt", "ccNC_a_notice.txt"}) {
		t.Errorf("%v %v", comps, notices)
	}
}

func TestSourceProduct(t *testing.T) {
	dirs := []string{"0109_AVNT5W_DaudioKK_kernel.lk", "0254_AVNT5W_TCC803XKK_platform.external.x", "ccNC_linux-4.9"}
	if got := sourceProduct(dirs); got != "AVNT5W (DaudioKK, TCC803XKK)" {
		t.Errorf("got %q", got)
	}
	if sourceProduct([]string{"ccNC_linux-4.9"}) != "" {
		t.Error("product from a tree with none")
	}
}

func TestGitDatesAndTitles(t *testing.T) {
	if got := normDate("fix hash check, Fri Sep 30 04:05:21 2022 +0000"); got != "2022-09-30" {
		t.Errorf("git date %q", got)
	}
	for in, want := range map[string]string{
		"[G5W][X-1] hash fix, Fri Sep 30 04:05:21 2022 +0000":                    "[G5W][X-1] hash fix",
		"[A] decrypt step - Issue Detail : text, Mon Aug 23 19:36:40 2021 +0900": "[A] decrypt step",
		"add driver, 2023. 07. 20":                                               "add driver",
	} {
		if got := cleanTitle(in); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
	if !duplicate("Pull request #707: x") || !duplicate(`Merge "x"`) || duplicate("add driver") {
		t.Error("duplicate")
	}
}

func TestRecent(t *testing.T) {
	mods := []secMod{{"2019-01-01", "old"}, {"2022-01-01", "new"}, {"", "undated"}}
	got := recent(mods, 2)
	if len(got) != 3 || got[0] != "new" || got[1] != "old" || got[2] != "(1 older not shown)" {
		t.Errorf("%v", got)
	}
}

func TestStorageAndTickets(t *testing.T) {
	if !storage.MatchString("[tcc803x][BSP][AVNG5WIDE-281732] add securedata partition format when factory reset") ||
		storage.MatchString("Fix the status display") {
		t.Error("storage filter")
	}
	got := ticketCounts(map[string]int{"OTAPLAT": 30, "AVNG5WIDE": 212, "BSP": 30})
	if got != "AVNG5WIDE (212), BSP (30), OTAPLAT (30)" {
		t.Errorf("tickets %q", got)
	}
	m := ticket.FindAllStringSubmatch("[G5W][OTAPLAT-1486] SecureBoot [AVNG5WIDE-1]", -1)
	if len(m) != 2 || m[0][1] != "OTAPLAT" {
		t.Errorf("ticket match %v", m)
	}
}

func TestStorageIgnoresBareFormat(t *testing.T) {
	if storage.MatchString("3GPP format for MO SMS shall be used") {
		t.Error("bare format matched")
	}
}

func TestNoticeDeclaredPaths(t *testing.T) {
	s := ParseNotice([]byte("Kenneth Heafield\n/* File Path 1: util/bit_packing.hh via kenlm_5bf7b46.patch */\n/* Copyright (c) 2024 42dot Inc. */\n"))
	if !reflect.DeepEqual(s.Paths, []string{"util/bit_packing.hh"}) {
		t.Errorf("paths %v", s.Paths)
	}
	s = ParseNotice([]byte("/*\n * File path1 : ./a/b.c\n * File path2 : d.c\n */\n====================\nModification: x\nDate: 2020-01-01\n\nu-boot/x.c\n"))
	if !reflect.DeepEqual(s.Paths, []string{"a/b.c", "d.c", "u-boot/x.c"}) {
		t.Errorf("paths %v", s.Paths)
	}
}

func TestNoticeTreeDumpIsNotChanges(t *testing.T) {
	in := "====================\nModification: Initialize uboot\nDate: 2017-10\n\n./Makefile\n./README\n├── ./api/Makefile\n└── ./api/README\n====================\nModification: real change\nDate: 2018-11-27\n\nu-boot/HowToBuild\n"
	s := ParseNotice([]byte(in))
	if !s.Import || !reflect.DeepEqual(s.Paths, []string{"u-boot/HowToBuild"}) {
		t.Errorf("paths %v", s.Paths)
	}
	if len(s.Mods) != 2 || s.Mods[0].Files != nil || len(s.Mods[1].Files) != 1 {
		t.Errorf("mods %+v", s.Mods)
	}
}
