package edl

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/secboot"
)

var pk = strings.Repeat("ab", 32)

const v2Session = "main - Using loader /x/prog.elf ...\n" +
	"main - Mode detected: sahara\n" +
	"sahara - Protocol version: 2, Version supported: 1\n" +
	"sahara - \x1b[32m\nVersion 0x2\n------------------------\n" +
	"HWID:              0x0016f0e102e80000 (MSM_ID:0x0016f0e1,OEM_ID:0x02e8,MODEL_ID:0x0000)\n" +
	"CPU detected:      \"SM6225\"\n" +
	"PK_HASH:           0x" + "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB" + "\n" +
	"Serial:            0x1a2b3c4d\n\x1b[0m" +
	"Parsing Lun 0:\n"

var v3Session = "main - Mode detected: sahara\n" +
	"sahara - Protocol version: 3, Version supported: 3\n" +
	"sahara - \nReading Chip Info : OK\n" +
	"sahara - - Sahara version  : 3\n" +
	"sahara - - Chip Serial Number : 99887766\n" +
	"sahara - - Chip Identifier V3 : 00000001\n" +
	"sahara - - MSM HWID : 0x001b80e1 | model_id:0x0000 | oem_id:02e8\n" +
	"sahara - - OEM PKHASH : " + "ab" + strings.Repeat("ab", 47) + "\n" +
	"sahara - - HW_ID : 001b80e102e80000\n"

func TestParseSaharaInfoV2(t *testing.T) {
	c := ParseSaharaInfo(v2Session)
	if c == nil {
		t.Fatal("nil")
	}
	if c.Mode != "sahara" || c.SaharaVersion != 2 || c.Serial != "1a2b3c4d" || c.PKHash != pk {
		t.Fatalf("got %+v", c)
	}
	if c.JTAGID() != "0016F0E1" || c.OEMID() != "02E8" || c.ModelID() != "0000" || !c.Fused() {
		t.Fatalf("ids %s %s %s", c.JTAGID(), c.OEMID(), c.ModelID())
	}
}

func TestParseSaharaInfoV3(t *testing.T) {
	c := ParseSaharaInfo(v3Session)
	if c == nil || c.SaharaVersion != 3 || c.Serial != "99887766" || c.JTAGID() != "001B80E1" || len(c.PKHash) != 96 {
		t.Fatalf("got %+v", c)
	}
}

func TestParseSaharaInfoFirehose(t *testing.T) {
	c := ParseSaharaInfo("main - Mode detected: firehose\nfirehose - ...\n")
	if c == nil || c.Mode != "firehose" || c.HWID != "" {
		t.Fatalf("got %+v", c)
	}
	if ParseSaharaInfo("nothing useful") != nil {
		t.Fatal("expected nil")
	}
}

func TestParseHelperOutput(t *testing.T) {
	c, err := parseHelperOutput("noise\n" + saharaMarker +
		`{"mode":"sahara","sahara_version":2,"serial":"1A2B3C4D","hwid":"0016F0E102E80000","pkhash":"` + pk + `"}` + "\n")
	if err != nil || c.Serial != "1a2b3c4d" || c.JTAGID() != "0016F0E1" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := parseHelperOutput(saharaMarker + `{"mode":"sahara","error":"refused"}`); err == nil {
		t.Fatal("want error")
	}
	if _, err := parseHelperOutput("no marker"); err == nil {
		t.Fatal("want error")
	}
}

func TestJudge(t *testing.T) {
	chip := &ChipInfo{HWID: "0016f0e102e80000", PKHash: pk}
	match := &secboot.Identity{OEMID: "02E8", JTAGID: "0016F0E1", RootSHA256: pk}
	if v := Judge(chip, match); !v.Accept || !v.Proven || len(v.Reasons) != 0 {
		t.Fatalf("match: %+v", v)
	}
	wrongRoot := &secboot.Identity{OEMID: "02E8", RootSHA256: strings.Repeat("cd", 32)}
	if v := Judge(chip, wrongRoot); v.Accept || !v.Proven {
		t.Fatalf("wrong root: %+v", v)
	}
	wrongOEM := &secboot.Identity{OEMID: "0072", RootSHA256: pk}
	if v := Judge(chip, wrongOEM); v.Accept {
		t.Fatalf("wrong oem: %+v", v)
	}
	// SM6225 fuses SHA-384 over a root signed with SHA-256.
	chip384 := &ChipInfo{HWID: "001b80e102e80000", PKHash: strings.Repeat("ab", 48)}
	sha384 := &secboot.Identity{OEMID: "02E8", RootSHA256: pk, RootSHA384: strings.Repeat("ab", 48)}
	if v := Judge(chip384, sha384); !v.Accept || !v.Proven {
		t.Fatalf("sha384: %+v", v)
	}
	oddLen := &ChipInfo{HWID: "0016f0e102e80000", PKHash: strings.Repeat("ab", 20)}
	if v := Judge(oddLen, match); !v.Accept || v.Proven {
		t.Fatalf("odd length: %+v", v)
	}
	unfused := &ChipInfo{HWID: "0016f0e102e80000", PKHash: strings.Repeat("0", 64)}
	if v := Judge(unfused, wrongRoot); !v.Accept {
		t.Fatalf("unfused: %+v", v)
	}
}

// The fused identity and a signed image's identity meet as the same facts, so
// an image signed for other silicon surfaces as an ordinary conflict.
func TestChipFactsConflictWithImage(t *testing.T) {
	b := facts.NewBag()
	facts.Set(b, SourceEDL, &Session{Chip: &ChipInfo{HWID: "0016f0e102e80000", PKHash: pk}},
		facts.Provenance{Source: "edl", Authority: facts.Attested})
	facts.Set(b, facts.JTAGID, "001B80E1", facts.Provenance{Source: "signed image", Authority: facts.Attested})
	res := facts.New(FactProviders(), nil).ResolveAll(b, facts.Options{})
	if got, _ := facts.Get(b, facts.OEMID); got != "02E8" {
		t.Fatalf("oem_id = %q", got)
	}
	found := false
	for _, f := range res.Findings {
		for _, name := range f.Facts {
			if name == facts.JTAGID.Name() {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no jtag_id conflict in %+v", res.Findings)
	}
}

func TestSessionCacheRoundTrip(t *testing.T) {
	r := &Runner{dir: t.TempDir()}
	if r.loadCache() != nil {
		t.Fatal("empty dir should have no cache")
	}
	chip := &ChipInfo{HWID: "0016f0e102e80000", PKHash: pk, SaharaVersion: 2, Serial: "1a2b3c4d"}
	r.saveCache(&sessionCache{StorageSerial: "12345", Chip: chip, Loader: "/x/prog.elf", Memory: "ufs"})
	c := r.loadCache()
	if c == nil || c.StorageSerial != "12345" || c.Chip.JTAGID() != "0016F0E1" || c.Loader != "/x/prog.elf" || c.When.IsZero() {
		t.Fatalf("got %+v", c)
	}
}

func TestStorageSerialRegex(t *testing.T) {
	out := `firehose - {"storage_info": {"total_blocks":30539776, "block_size":4096, "serial_num":2748219168, "mem_type":"UFS"}}`
	if m := reStorageSerial.FindStringSubmatch(out); m == nil || m[1] != "2748219168" {
		t.Fatalf("got %v", m)
	}
}
