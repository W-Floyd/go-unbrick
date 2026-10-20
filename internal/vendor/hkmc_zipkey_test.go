package vendor

import (
	"archive/zip"
	"bytes"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/zipcrypto"
)

// storedZip is a zip of one stored, unencrypted member.
func storedZip(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	w.Write(body)
	zw.Close()
	return buf.Bytes()
}

// encryptedZip is a zip whose one member is stored and encrypted with the
// traditional cipher, as the package's encapsuled.zip is.
func encryptedZip(t *testing.T, name string, plain []byte, password string, mod time.Time) []byte {
	t.Helper()
	crc := crc32.ChecksumIEEE(plain)
	enc := zipcrypto.Encrypt(plain, []byte(password), byte(crc>>24))
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{Name: name, Method: zip.Store, Flags: 0x1, CRC32: crc,
		CompressedSize64: uint64(len(enc)), UncompressedSize64: uint64(len(plain)), Modified: mod})
	if err != nil {
		t.Fatal(err)
	}
	w.Write(enc)
	zw.Close()
	return buf.Bytes()
}

// packageZip is the shape of a taxi head-unit package: UpdateFiles/ holding an
// inventory and an encapsuled.zip whose one member is encrypted with the date.
func packageZip(t *testing.T, fileName, fwinfo, password string, entry time.Time) string {
	t.Helper()
	ota := storedZip(t, "META-INF/com/android/metadata", []byte("ota-type=AB\n"))
	capsule := encryptedZip(t, "ota.zip", ota, password, entry)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store, Modified: entry})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	add("UpdateFiles/fwinfo.ini", []byte(fwinfo))
	add("UpdateFiles/encapsuled.zip", capsule)
	zw.Close()
	p := filepath.Join(t.TempDir(), fileName)
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func memberNames(t *testing.T, n *carve.Node) []string {
	t.Helper()
	_, kids, err := n.Children()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range kids {
		out = append(out, k.Name)
	}
	return out
}

func withZipPasswords(t *testing.T) {
	old := carve.ZipPasswords
	carve.ZipPasswords = ZipPasswords
	t.Cleanup(func() { carve.ZipPasswords = old })
}

const fwinfo = "CPU.name = mtx_tcc803xp_arm64-ota-eng.hsw0620.zip\nCPU.version = 2\nCPU.timestamp = 202601071722\nCPU.theme = KIA\n"

func TestPackagePasswordIsTheDateWithoutTheCentury(t *testing.T) {
	withZipPasswords(t)
	entry := time.Date(2026, 1, 7, 8, 30, 0, 0, time.UTC)
	p := packageZip(t, "MS400A_KIA_202601071722_x.zip", fwinfo, "260107", entry)
	root, err := carve.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := root.Walk("UpdateFiles/encapsuled.zip")
	if err != nil {
		t.Fatal(err)
	}
	if got := memberNames(t, cap); len(got) != 1 || got[0] != "ota.zip" {
		t.Fatalf("encapsuled.zip: %v", got)
	}
	// And through the decrypted member to the OTA zip's own.
	ota, err := root.Walk("UpdateFiles/encapsuled.zip/ota.zip")
	if err != nil {
		t.Fatal(err)
	}
	if got := memberNames(t, ota); len(got) != 1 || got[0] != "META-INF/com/android/metadata" {
		t.Errorf("the decrypted OTA zip: %v", got)
	}
	m, _ := ota.Walk("META-INF/com/android/metadata")
	if data, _, _ := readAll(m); string(data) != "ota-type=AB\n" {
		t.Errorf("decrypted content: %q", data)
	}
}

func readAll(n *carve.Node) ([]byte, bool, error) {
	r, err := n.Reader()
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	var b bytes.Buffer
	_, err = b.ReadFrom(r)
	return b.Bytes(), false, err
}

// The date is in three places; any one is enough.
func TestPasswordFromAnyOfTheThreeDates(t *testing.T) {
	withZipPasswords(t)
	cases := map[string]struct {
		file, ini string
		entry     time.Time
	}{
		"inventory only":  {"package.zip", fwinfo, time.Date(2030, 5, 5, 0, 0, 0, 0, time.UTC)},
		"file name only":  {"MS400A_KIA_202601071722_x.zip", "CPU.name = a\n", time.Date(2030, 5, 5, 0, 0, 0, 0, time.UTC)},
		"entry date only": {"package.zip", "CPU.name = a\n", time.Date(2026, 1, 7, 8, 30, 0, 0, time.UTC)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := packageZip(t, c.file, c.ini, "260107", c.entry)
			root, _ := carve.Open(p)
			ota, err := root.Walk("UpdateFiles/encapsuled.zip/ota.zip")
			if err != nil {
				t.Fatal(err)
			}
			if got := memberNames(t, ota); len(got) != 1 {
				t.Errorf("not opened: %v", got)
			}
		})
	}
}

// A date that is not the password leaves the member as stored: its bytes are the
// ciphertext, and nothing claims to open it.
func TestWrongPasswordLeavesTheMemberAsStored(t *testing.T) {
	withZipPasswords(t)
	p := packageZip(t, "MS400A_KIA_202601071722_x.zip", fwinfo, "not-a-date", time.Date(2026, 1, 7, 8, 30, 0, 0, time.UTC))
	root, _ := carve.Open(p)
	cap, err := root.Walk("UpdateFiles/encapsuled.zip")
	if err != nil {
		t.Fatal(err)
	}
	_, kids, err := cap.Children()
	if err != nil || len(kids) != 1 {
		t.Fatalf("%v %v", kids, err)
	}
	if _, inner, _ := kids[0].Children(); len(inner) != 0 {
		t.Errorf("a wrong password opened it: %d members", len(inner))
	}
}

func TestStampsAreFoundInNamesAndInventories(t *testing.T) {
	if got := stampsIn("MS400A_KIA_202601071722_운영_프로필 전환 상품성 개선.zip"); len(got) != 1 || got[0] != "260107" {
		t.Errorf("file name: %v", got)
	}
	if got := fwinfoStamps(carve.FromBytes("fwinfo.ini", []byte(fwinfo))); len(got) != 1 || got[0] != "260107" {
		t.Errorf("inventory: %v", got)
	}
	if got := stampsIn("v20261301_x"); len(got) != 0 {
		t.Errorf("a month 13 is not a date: %v", got)
	}
}
