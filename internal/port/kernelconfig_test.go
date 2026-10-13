package port

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func kernelWithConfig(t *testing.T, cfg string, wrap bool) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write([]byte(cfg))
	zw.Close()
	img := append([]byte("junkjunk Linux version 4.19.157-perf IKCFG_ST"), z.Bytes()...)
	img = append(img, []byte("IKCFG_ED tail")...)
	if !wrap {
		return img
	}
	var w bytes.Buffer
	gw := gzip.NewWriter(&w)
	gw.Write(img)
	gw.Close()
	return w.Bytes()
}

const sampleConfig = `CONFIG_ARCH_BENGAL=y
CONFIG_CMDLINE="cgroup_disable=pressure"
CONFIG_TOUCHSCREEN_HIMAX_COMMON=y
# CONFIG_TOUCHSCREEN_NOVATEK_NT36XXX is not set
CONFIG_CHARGE_BQ2589X=y
`

func TestKernelConfigFromPlainAndGzippedImages(t *testing.T) {
	for _, wrap := range []bool{false, true} {
		cfg := KernelConfig(KernelImage(kernelWithConfig(t, sampleConfig, wrap)))
		if cfg["CONFIG_ARCH_BENGAL"] != "y" || cfg["CONFIG_CMDLINE"] != "cgroup_disable=pressure" || cfg["CONFIG_TOUCHSCREEN_NOVATEK_NT36XXX"] != "n" {
			t.Errorf("wrapped=%v: %v", wrap, cfg)
		}
	}
	if KernelConfig([]byte("a kernel with no config")) != nil {
		t.Error("no IKCFG_ST should be nil")
	}
}

func TestConfigTextRoundTrips(t *testing.T) {
	cfg := KernelConfig(kernelWithConfig(t, sampleConfig, false))
	text := ConfigText(cfg)
	for _, want := range []string{"CONFIG_CMDLINE=\"cgroup_disable=pressure\"", "# CONFIG_TOUCHSCREEN_NOVATEK_NT36XXX is not set", "CONFIG_ARCH_BENGAL=y"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
}

func TestConfigEvidence(t *testing.T) {
	p := Package{KernelConfig: map[string]string{
		"CONFIG_CHARGE_BQ2589X":              "y",
		"CONFIG_TOUCHSCREEN_HIMAX_COMMON":    "y",
		"CONFIG_TOUCHSCREEN_NOVATEK_NT36XXX": "n",
		"CONFIG_DEVFREQ_SIMPLE_DEV":          "y",
		"CONFIG_PINCTRL_QCOM_SPMI_PMIC":      "y",
	}}
	if en, _, weak := p.ConfigEvidence("ti,bq2589x-1"); len(en) != 1 || weak {
		t.Errorf("name match: %v weak=%v", en, weak)
	}
	if en, _, weak := p.ConfigEvidence("himax,hxcommon"); len(en) != 1 || !weak {
		t.Errorf("vendor-only: %v weak=%v", en, weak)
	}
	// A disabled symbol is evidence only when the name matches the part; a
	// disabled symbol of the same vendor alone says nothing.
	if _, dis, weak := p.ConfigEvidence("novatek,nt36xxx"); len(dis) != 1 || weak {
		t.Errorf("disabled: %v weak=%v", dis, weak)
	}
	if en, dis, _ := p.ConfigEvidence("novatek,NVT-ts"); len(en)+len(dis) != 0 {
		t.Errorf("vendor-only disabled: %v %v", en, dis)
	}
	// A generic binding and the qcom vendor carry no evidence.
	for _, c := range []string{"simple-battery", "qcom,i2c-pmic"} {
		if en, dis, _ := p.ConfigEvidence(c); len(en)+len(dis) != 0 {
			t.Errorf("%s: %v %v", c, en, dis)
		}
	}
}
