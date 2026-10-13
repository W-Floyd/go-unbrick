package port

import (
	"strings"
	"testing"
)

const ucmMixer = `<mixer>
    <ctl name="aw_dev_0_switch" value="Disable" />
    <ctl name="Gain" id="0" value="0" />
    <ctl name="Gain" id="1" value="0" />
    <path name="speaker">
        <ctl name="aw_dev_0_switch" value="Enable" />
        <ctl name="Gain" id="0" value="20" />
        <ctl name="Gain" id="1" value="21" />
        <ctl name="No Reset" value="1" />
    </path>
</mixer>`

func ucmPackage(t *testing.T) Package {
	t.Helper()
	mp, err := ParseMixerPaths([]byte(ucmMixer))
	if err != nil {
		t.Fatal(err)
	}
	return Package{
		Props: map[string]string{"ro.product.vendor.device": "tb"},
		Audio: &Audio{Files: []AudioFile{{
			Name: "etc/mixer_paths.xml", Mixer: mp,
			Interfaces: map[string]string{"SND_DEVICE_OUT_SPEAKER": "WSA_CDC_DMA_RX_0"},
		}}},
	}
}

func TestUCMDraftsADeviceFromAStockPath(t *testing.T) {
	files, notes := UCM(ucmPackage(t))
	hifi := string(files["ucm/tb/HiFi.conf"])
	for _, want := range []string{
		`SectionDevice."Speaker" {`,
		`cset "name='aw_dev_0_switch' Enable"`,
		`cset "name='Gain' 20,21"`, // an array control set by id, values in order
		`cset "name='aw_dev_0_switch' Disable"`,
		`cset "name='Gain' 0,0"`, // restored to the stock initial values
		`# TODO: no stock initial value to restore for: No Reset`,
		`the stock DAI is WSA_CDC_DMA_RX_0`,
		`# TODO: the card's name is the codename`,
	} {
		if !strings.Contains(hifi, want) {
			t.Errorf("HiFi.conf lacks %q:\n%s", want, hifi)
		}
	}
	if !strings.Contains(string(files["ucm/tb/tb.conf"]), `File "HiFi.conf"`) {
		t.Errorf("card conf: %s", files["ucm/tb/tb.conf"])
	}
	if strings.Contains(hifi, `SectionDevice."Earpiece"`) {
		t.Error("a device with no stock path must not be drafted")
	}
	if len(notes) != 2 {
		t.Errorf("notes: %v", notes)
	}
	if f, n := UCM(Package{}); f != nil || n != nil {
		t.Error("no audio, no files")
	}
}

func TestCsetsLeavesWhatItCannotSayForAPerson(t *testing.T) {
	lines, notes := csets([]MixerCtl{
		{"Gap", "0", "1"}, {"Gap", "2", "3"}, // id 1 missing
		{"Mode", "", "two words"},
		{"Ok", "", "On"},
	})
	if len(lines) != 1 || lines[0] != `cset "name='Ok' On"` || len(notes) != 2 {
		t.Errorf("lines %v notes %v", lines, notes)
	}
}

func TestUCMCardNameIsTheLiveCardWhenKnown(t *testing.T) {
	p := ucmPackage(t)
	p.Live = &Live{SoundCards: []SoundCard{{Name: "card0", ID: "bengal-snd-card"}}}
	files, _ := UCM(p)
	hifi := string(files["ucm/bengal-snd-card/HiFi.conf"])
	if hifi == "" || strings.Contains(hifi, "the card's name is the codename") {
		t.Errorf("live card name not used:\n%v", files)
	}
}
