package upstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseName(t *testing.T) {
	cases := []struct {
		name                          string
		ok                            bool
		jtag, oem, model, pk, variant string
	}{
		{"0016f0e102e80000_a51a1c2e4a5ec0f8_fhprg.bin", true, "0016F0E1", "02E8", "0000", "a51a1c2e4a5ec0f8", ""},
		{"000ba0e102e80000_4aac65a9be0cf870_fhprg_peek.bin", true, "000BA0E1", "02E8", "0000", "4aac65a9be0cf870", "peek"},
		{"001b80e102e80000_8b2d1c830d9d8576_fhprg_moto_g52.bin", true, "001B80E1", "02E8", "0000", "8b2d1c830d9d8576", "moto_g52"},
		{"0008c0e100010000_a7b8b82545a98eca_fhprg_edlauth.bin", true, "0008C0E1", "0001", "0000", "a7b8b82545a98eca", "edlauth"},
		{".gitignore", false, "", "", "", "", ""},
		{"__init__.py", false, "", "", "", "", ""},
		{"putyourloadersinhere.txt", false, "", "", "", "", ""},
		{"deadbeef_short_fhprg.bin", false, "", "", "", "", ""}, // wrong hex widths
	}
	for _, c := range cases {
		e, ok := parseName(c.name)
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.name, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if e.JTAGID != c.jtag || e.OEMID != c.oem || e.ModelID != c.model || e.PKHASH != c.pk || e.Variant != c.variant {
			t.Errorf("%s: got %+v", c.name, e)
		}
	}
}

func TestStockFiltersResearchBuilds(t *testing.T) {
	stock, _ := parseName("0016f0e102e80000_a51a1c2e4a5ec0f8_fhprg.bin")
	peek, _ := parseName("000ba0e102e80000_4aac65a9be0cf870_fhprg_peek.bin")
	auth, _ := parseName("0008c0e100010000_a7b8b82545a98eca_fhprg_edlauth.bin")
	if !stock.Stock() || peek.Stock() || auth.Stock() {
		t.Errorf("Stock(): stock=%v peek=%v auth=%v", stock.Stock(), peek.Stock(), auth.Stock())
	}
}

func TestListDecodesAndFiltersByOEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/lenovo_motorola") {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode([]ghContent{
			{Name: "0016f0e102e80000_a51a1c2e4a5ec0f8_fhprg.bin", Type: "file", Size: 100, DownloadURL: "http://x/a"},
			{Name: "0008c0e100010000_a7b8b82545a98eca_fhprg.bin", Type: "file", Size: 200, DownloadURL: "http://x/b"}, // OEM 0001, filtered out
			{Name: "GM", Type: "dir"},
			{Name: ".gitignore", Type: "file", Size: 5},
		})
	}))
	defer srv.Close()

	got, err := listFrom(context.Background(), srv.URL+"/", "lenovo_motorola", []string{"02E8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 (only OEM 02E8, no dirs/junk), got %d: %+v", len(got), got)
	}
	if got[0].JTAGID != "0016F0E1" || got[0].Size != 100 || got[0].DownloadURL != "http://x/a" {
		t.Errorf("entry not decoded: %+v", got[0])
	}
}
