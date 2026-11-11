package vendor

import (
	"reflect"
	"testing"
)

func TestParseFjhdmiUpdateIni(t *testing.T) {
	data := []byte("#MODEL_TYPE = FBDMI\n#UPDATE_VERSION = FBDMI_1.3.13_2022.03.08\n#SYSTEM_UPDATE = 1\n#MICOM_UPDATE = 1\n")
	got := ParseFjhdmiUpdateIni(data)
	want := FjhdmiInfo{ModelType: "FBDMI", UpdateVersion: "FBDMI_1.3.13_2022.03.08", SystemUpdate: true, MicomUpdate: true}
	if got != want {
		t.Fatalf("ParseFjhdmiUpdateIni = %+v, want %+v", got, want)
	}
}

func TestParseFjhdmiUpdateIniPartial(t *testing.T) {
	got := ParseFjhdmiUpdateIni([]byte("#MODEL_TYPE = X\n#SYSTEM_UPDATE = 0\n"))
	want := FjhdmiInfo{ModelType: "X", SystemUpdate: false}
	if got != want {
		t.Fatalf("ParseFjhdmiUpdateIni = %+v, want %+v", got, want)
	}
}

func TestParseFjhdmiManifest(t *testing.T) {
	hashIni := "30c44a60915701348bb5c2ff958fe609c4c5a1bf0ed48c246fadcfab4c1e744a7f1de975927e7feab8b80163a285f3ea7525b743a1715aff805080bd15a7ed13"
	hashZip := "9d7a8294122e546242ac4a615fbe0ccb4f1f08ceebbd023f2ab843d98f5c2a3b6ea2807fd889670504b3482fa0ab9e6f1fa9ac229a8452ec7a219d67e9bd2a02"
	data := []byte(hashIni + " *./update.ini\n" + hashZip + " *./update.zip\n")
	got := ParseFjhdmiManifest(data)
	want := []FjhdmiManifestEntry{
		{Hash: hashIni, Name: "./update.ini"},
		{Hash: hashZip, Name: "./update.zip"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseFjhdmiManifest = %+v, want %+v", got, want)
	}
}

func TestParseFjhdmiManifestPlainFormat(t *testing.T) {
	hash := "30c44a60915701348bb5c2ff958fe609c4c5a1bf0ed48c246fadcfab4c1e744a7f1de975927e7feab8b80163a285f3ea7525b743a1715aff805080bd15a7ed13"
	got := ParseFjhdmiManifest([]byte(hash + "  update.ini\n"))
	want := []FjhdmiManifestEntry{{Hash: hash, Name: "update.ini"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseFjhdmiManifest = %+v, want %+v", got, want)
	}
}

func TestAlpineZipPasswords(t *testing.T) {
	for _, tc := range []struct {
		name   string
		member string
		want   bool
	}{
		{"manifest", "fbdmisha512", true},
		{"inventory", "update.ini", true},
		{"payload", "update.zip", true},
		{"nested payload path", "iLX-F411/fjhdmi20.update/update.zip", true},
		{"case-insensitive", "UPDATE.INI", true},
		{"unrelated member", "boot.img", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pws := alpine{}.ZipPasswords(nil, tc.member)
			got := len(pws) > 0
			if got != tc.want {
				t.Fatalf("ZipPasswords(%q) returned %v, want non-empty=%v", tc.member, pws, tc.want)
			}
			if got && pws[0] != "FBDMI" {
				t.Fatalf("password = %q, want %q", pws[0], "FBDMI")
			}
		})
	}
}

func TestAlpineRegistered(t *testing.T) {
	for _, d := range Drivers() {
		if d.ID() == "alpine" {
			if d.Platform() != PlatformTelechips {
				t.Fatalf("alpine Platform() = %q, want %q", d.Platform(), PlatformTelechips)
			}
			return
		}
	}
	t.Fatal("alpine driver not registered")
}
