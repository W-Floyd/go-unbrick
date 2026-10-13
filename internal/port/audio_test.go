package port

import (
	"fmt"
	"strings"
	"testing"
)

const mixerXML = `<?xml version="1.0" encoding="ISO-8859-1"?>
<mixer>
    <ctl name="Initial" value="0" />
    <path name="speaker">
        <ctl name="aw_dev_0_switch" value="Enable" />
        <ctl name="aw_dev_1_switch" value="Enable" />
    </path>
    <path name="handset-mic">
        <path name="amic1" />
        <ctl name="TX_DEC0 Volume" id="0" value="84" />
    </path>
    <path name="amic1">
        <ctl name="TX DEC0 MUX" value="SWR_MIC" />
    </path>
</mixer>`

const platformXML = `<audio_platform_info>
  <acdb_ids><device name="SND_DEVICE_OUT_SPEAKER" acdb_id="15"/></acdb_ids>
  <backend_names>
    <device name="SND_DEVICE_OUT_SPEAKER" interface="WSA_CDC_DMA_RX_0"/>
    <device name="SND_DEVICE_IN_HANDSET_MIC" interface="TX_CDC_DMA_TX_3"/>
  </backend_names>
</audio_platform_info>`

func TestParseMixerPathsResolvesNestedPaths(t *testing.T) {
	mp, err := ParseMixerPaths([]byte(mixerXML))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mp.Paths["Initial"]; ok || len(mp.Paths) != 3 {
		t.Errorf("controls outside a path are not a path: %v", mp.Paths)
	}
	spk, _ := mp.Resolve("speaker")
	if len(spk) != 2 || spk[0].String() != "aw_dev_0_switch=Enable" {
		t.Errorf("speaker: %v", spk)
	}
	mic, ok := mp.Resolve("handset-mic")
	if !ok || len(mic) != 2 || mic[0].String() != "TX_DEC0 Volume[0]=84" || mic[1].Name != "TX DEC0 MUX" {
		t.Errorf("handset-mic with its own control and the nested amic1: %v", mic)
	}
	if _, ok := mp.Resolve("nope"); ok {
		t.Error("missing path resolved")
	}
}

func TestPlatformInterfacesTakesTheInterfaceAttribute(t *testing.T) {
	m, err := PlatformInterfaces([]byte(platformXML))
	if err != nil {
		t.Fatal(err)
	}
	if m["SND_DEVICE_OUT_SPEAKER"] != "WSA_CDC_DMA_RX_0" || m["SND_DEVICE_IN_HANDSET_MIC"] != "TX_CDC_DMA_TX_3" || len(m) != 2 {
		t.Errorf("got %v", m)
	}
}

func TestReadAudioPairsMixerAndPlatformFiles(t *testing.T) {
	read := func(name string) ([]byte, error) {
		switch name {
		case "etc/mixer_paths.xml", "etc/mixer_paths_qrd.xml":
			return []byte(mixerXML), nil
		case "etc/audio_platform_info.xml":
			return []byte(platformXML), nil
		}
		return nil, fmt.Errorf("no %s", name)
	}
	a := ReadAudio([]string{"etc/mixer_paths_qrd.xml", "etc/mixer_paths.xml", "etc/other.xml"}, read)
	if a == nil || len(a.Files) != 2 {
		t.Fatalf("got %+v", a)
	}
	var plain AudioFile
	for _, f := range a.Files {
		if f.Name == "etc/mixer_paths.xml" {
			plain = f
		}
	}
	if plain.Interfaces["SND_DEVICE_OUT_SPEAKER"] != "WSA_CDC_DMA_RX_0" {
		t.Errorf("platform file for the plain mixer: %v", plain.Interfaces)
	}
	sec := AudioSection(a)
	if !strings.Contains(sec, "| speaker | WSA_CDC_DMA_RX_0 | `aw_dev_0_switch=Enable`") {
		t.Errorf("section:\n%s", sec)
	}
	if ReadAudio([]string{"etc/other.xml"}, read) != nil {
		t.Error("no mixer file should give nil")
	}
}
