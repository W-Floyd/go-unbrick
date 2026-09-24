package transport

import (
	"reflect"
	"testing"
)

func TestParseSoCImages(t *testing.T) {
	in := "0:\n\tCRM:\t\t00:BOOT.XF.4.1-00374-KAMORTALAZ-1\n\tVariant:\tKamortaLAA\n\tVersion:\t:build-host\n" +
		"1:\n\tCRM:\t\t00:TZ.XF.5.1.6-82754-2\n\tVariant:\t\n\tVersion:\t\n" +
		"2:\n\tCRM:\t\t\n\tVariant:\t\n\tVersion:\t\n" +
		"27:\n\tCRM:\t\tX\n\tVariant:\t\n\tVersion:\t\n"
	want := []FWImage{
		{Name: "boot", CRM: "BOOT.XF.4.1-00374-KAMORTALAZ-1", Variant: "KamortaLAA", OEM: "build-host"},
		{Name: "tz", CRM: "TZ.XF.5.1.6-82754-2"},
		{Name: "27", CRM: "X"},
	}
	if got := ParseSoCImages(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestParseDebugfsImages(t *testing.T) {
	in := "boot\tBOOT.XF.4.1\tKamortaLAA\thost\nmpss\tMPSS.HA.1\t\t\ncdsp\t\t\t\n"
	want := []FWImage{
		{Name: "boot", CRM: "BOOT.XF.4.1", Variant: "KamortaLAA", OEM: "host"},
		{Name: "mpss", CRM: "MPSS.HA.1"},
	}
	if got := ParseDebugfsImages(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}
