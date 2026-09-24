package adb

import (
	"strings"
	"testing"
)

// pmOutput is what the package-manager collection returns, shaped like a real
// device's: image APKs under /product and /system_ext, a delivery agent's
// installs under /data/app, one package already uninstalled for user 0 and one
// disabled.
const pmOutput = `
===unbrick:packages===
package:/system_ext/priv-app/Phone/Phone.apk=com.android.phone
package:/product/app/Aura/Aura.apk=com.aura.oobe.motorola
package:/product/app/FMRadio/FMRadio.apk=com.motorola.android.fmradio
package:/data/app/~~kO6w==/com.einnovation.temu-Lm3==/base.apk=com.einnovation.temu
package:/product/app/Gone/Gone.apk=com.aura.jet.att
package:/product/app/Weather/Weather.apk=com.handmark.expressweather
===unbrick:system===
package:com.android.phone
package:com.motorola.android.fmradio
package:com.aura.oobe.motorola
package:com.aura.jet.att
===unbrick:disabled===
package:com.handmark.expressweather
===unbrick:uninstalled===
package:com.android.phone
package:com.aura.oobe.motorola
package:com.aura.jet.att
package:com.motorola.android.fmradio
package:com.einnovation.temu
package:com.handmark.expressweather
===unbrick:installed===
package:com.android.phone
package:com.aura.oobe.motorola
package:com.motorola.android.fmradio
package:com.einnovation.temu
package:com.handmark.expressweather
`

func find(t *testing.T, pkgs []Package, name string) Package {
	t.Helper()
	for _, p := range pkgs {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("%s missing from the parsed list", name)
	return Package{}
}

func TestParsePackages(t *testing.T) {
	pkgs := parsePackages(pmOutput)
	if len(pkgs) != 6 {
		t.Fatalf("parsed %d packages, want 6", len(pkgs))
	}

	phone := find(t, pkgs, "com.android.phone")
	if !phone.System || phone.APK != "/system_ext/priv-app/Phone/Phone.apk" {
		t.Errorf("com.android.phone = %+v", phone)
	}
	// A /data path full of '=' from the installer's directory names must not
	// confuse the name/path split, which takes the *last* '='.
	temu := find(t, pkgs, "com.einnovation.temu")
	if temu.System || !strings.HasPrefix(temu.APK, "/data/app/") {
		t.Errorf("com.einnovation.temu = %+v", temu)
	}
	if find(t, pkgs, "com.handmark.expressweather").Disabled != true {
		t.Error("the disabled package was not marked disabled")
	}
	// Listed by -u but absent from the plain list: already uninstalled for this
	// user, which is how a second run knows not to offer it again.
	if !find(t, pkgs, "com.aura.jet.att").Uninstalled {
		t.Error("an already-uninstalled package was not marked")
	}
	if find(t, pkgs, "com.aura.oobe.motorola").Uninstalled {
		t.Error("an installed package was marked uninstalled")
	}
}

// FromImage decides whether a removal can be undone locally, not whether a
// package is bloat.
func TestFromImage(t *testing.T) {
	pkgs := parsePackages(pmOutput)
	for _, name := range []string{"com.android.phone", "com.aura.oobe.motorola", "com.handmark.expressweather"} {
		if !find(t, pkgs, name).FromImage() {
			t.Errorf("%s: FromImage() = false, want true", name)
		}
	}
	// Delivered after setup: the APK is in /data, so removing it is permanent
	// until the Play Store is asked.
	if find(t, pkgs, "com.einnovation.temu").FromImage() {
		t.Error("a /data install was reported as coming from the image")
	}
}

func TestParsePackagesEmpty(t *testing.T) {
	if got := parsePackages(""); len(got) != 0 {
		t.Errorf("parsed %d packages from nothing", len(got))
	}
}

// The package manager's own words are what the operator needs: a refusal for a
// package the shell may not touch reads very differently from one a device
// policy protects.
func TestPMResult(t *testing.T) {
	if err := pmResult("uninstall", "com.x", "Success\n", nil); err != nil {
		t.Errorf("Success was read as a failure: %v", err)
	}
	err := pmResult("uninstall", "com.x", "Failure [DELETE_FAILED_DEVICE_POLICY_MANAGER]\n", nil)
	if err == nil {
		t.Fatal("a Failure line was read as success")
	}
	if !strings.Contains(err.Error(), "DELETE_FAILED_DEVICE_POLICY_MANAGER") {
		t.Errorf("error dropped the device's reason: %v", err)
	}
	if !strings.Contains(err.Error(), "com.x") {
		t.Errorf("error does not name the package: %v", err)
	}
}
