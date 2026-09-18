package cid

import "testing"

func TestParseHABMeta(t *testing.T) {
	cases := []struct {
		name     string
		blob     []byte
		codename string
		cid      uint16
		ok       bool
	}{
		{"avb-nul-separated", append([]byte("\x00\x10prop"), append([]byte("HAB_META\x00eqs_50\x00"), []byte("rest")...)...), "eqs", 50, true},
		{"contiguous", []byte("....HAB_METAfogona_51...."), "fogona", 51, true},
		{"underscored-codename", []byte("HAB_META\x00rav_ov_50\x00"), "rav_ov", 50, true},
		{"absent", []byte("no marker here"), "", 0, false},
		{"no-cid", []byte("HAB_META\x00eqs\x00"), "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := ParseHABMeta(tc.blob)
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v", ok, tc.ok)
			}
			if ok && (m.Codename != tc.codename || m.CID != tc.cid) {
				t.Errorf("got %q/%d, want %q/%d", m.Codename, m.CID, tc.codename, tc.cid)
			}
		})
	}
	if got := (HABMeta{CID: 50}).CIDHex(); got != "0x0032" {
		t.Errorf("CIDHex = %q, want 0x0032", got)
	}
}
