package imgfacts

import (
	"encoding/hex"
	"encoding/pem"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/facts"
)

const fstab = `# comment
/dev/block/by-name/metadata /metadata f2fs noatime wait,check,formattable,first_stage_mount
system /system erofs ro wait,slotselect,avb=vbmeta_system,logical,first_stage_mount,avb_keys=/avb/q-gsi.avbpubkey:/avb/r-gsi.avbpubkey:/avb/s-gsi.avbpubkey
/dev/block/bootdevice/by-name/userdata /data f2fs noatime,inlinecrypt latemount,wait,check,fileencryption=aes-256-xts:aes-256-cts:v2,keydirectory=/metadata/vold/metadata_encryption
`

func TestFstab(t *testing.T) {
	enc, meta, ok := fstabEncryption([]byte(fstab))
	if !ok || enc != "aes-256-xts:aes-256-cts:v2" || !meta {
		t.Errorf("encryption = %q %v %v", enc, meta, ok)
	}
	if got := fstabGSIKeys([]byte(fstab)); !slices.Equal(got, []string{"q-gsi", "r-gsi", "s-gsi"}) {
		t.Errorf("gsi keys = %v", got)
	}
	enc, _, _ = fstabEncryption([]byte("/dev/block/userdata /data ext4 noatime wait,forceencrypt=footer\n"))
	if enc != "full-disk" {
		t.Errorf("forceencrypt = %q", enc)
	}
}

func resolve(t *testing.T, files ...facts.File) *facts.Bag {
	t.Helper()
	b := facts.NewBag()
	for _, f := range files {
		facts.Recognize(b, Recognizers(), f)
	}
	g := facts.New(FactProviders(), Checks())
	g.ResolveAll(b, facts.Options{})
	return b
}

func TestMacPermissionsTestKey(t *testing.T) {
	p, err := os.ReadFile("testdata/aosp_platform.x509.pem")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(p)
	xml := `<?xml version="1.0" encoding="iso-8859-1"?><policy><signer signature="` + hex.EncodeToString(blk.Bytes) +
		`"><seinfo value="platform"/></signer></policy>`
	b := facts.NewBag()
	facts.Recognize(b, Recognizers(), facts.File{Name: "system/system/etc/selinux/plat_mac_permissions.xml", Data: []byte(xml)})
	res := facts.New(FactProviders(), Checks()).ResolveAll(b, facts.Options{})
	if v, _ := facts.Get(b, facts.PlatformCert); v != "c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8" {
		t.Errorf("platform cert = %s", v)
	}
	if who, _ := facts.Get(b, facts.PlatformSigner); who != "Android" {
		t.Errorf("signer = %q", who)
	}
	found := false
	for _, f := range res.Findings {
		found = found || f.Severity == facts.Error && strings.Contains(f.Message, "test keys for platform")
	}
	if !found {
		t.Errorf("no test-key finding: %+v", res.Findings)
	}
}

func TestPartitionProps(t *testing.T) {
	vendor := "ro.board.platform=bengal\nro.product.first_api_level=33\nro.vendor.build.version.release=13\nro.vendor.build.security_patch=2026-03-05\n"
	sku := func(model string) []byte {
		return []byte("ro.product.odm.model=" + model + "\nro.product.odm.marketname=Redmi Note 12\n")
	}
	b := resolve(t,
		facts.File{Name: "vendor/build.prop", Data: []byte(vendor)},
		facts.File{Name: "odm/etc/build.prop", Data: []byte("ro.product.odm.model=tapas\n")},
		facts.File{Name: "odm/etc/build_m7g.prop", Data: sku("23021RAAEG")},
		facts.File{Name: "odm/etc/build_m7in.prop", Data: sku("23021RAAEI")},
	)
	facts.Set(b, facts.SecurityPatch, "2026-08-01", facts.Provenance{Authority: facts.Attested})
	if v, _ := facts.Get(b, facts.BoardPlatform); v != "bengal" {
		t.Errorf("platform = %q", v)
	}
	if v, _ := facts.Get(b, facts.FirstAPILevel); v != 33 {
		t.Errorf("first api = %d", v)
	}
	m, _ := facts.Get(b, facts.SKUModels)
	if len(m) != 2 || m["m7g"] != "23021RAAEG" || m["m7in"] != "23021RAAEI" {
		t.Errorf("skus = %v", m)
	}
	if v, _ := facts.Get(b, facts.Model); v != "Redmi Note 12" {
		t.Errorf("model = %q", v)
	}
	fs := Checks()[0].Verify(b)
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "5 months behind") {
		t.Errorf("patch lag findings = %+v", fs)
	}
}

func TestBluetoothFirmware(t *testing.T) {
	b := resolve(t,
		facts.File{Name: "bluetooth/image/apbtfw10.tlv", Data: []byte{0}},
		facts.File{Name: "bluetooth/image/apbtfw11.tlv", Data: []byte{0}},
		facts.File{Name: "bluetooth/image/cmbtfw12.tlv", Data: []byte{0}},
		facts.File{Name: "bluetooth/image/cmbtfw13.tlv", Data: []byte{0}},
		facts.File{Name: "bluetooth/image/cmbtfw13.ver", Data: []byte("BTFM.CMC.1.3.0-00101\n")},
	)
	want := "Apache (10, 11), Comanche (12, 13; BTFM.CMC.1.3.0-00101)"
	if v, _ := facts.Get(b, facts.BluetoothFirmware); v != want {
		t.Errorf("bluetooth firmware = %q, want %q", v, want)
	}
}
