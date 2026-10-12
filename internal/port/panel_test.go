package port

import (
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

// cmd builds a stock command record: dtype last vc ack wait dlen(2) payload.
func cmd(dtype, wait byte, payload ...byte) []byte {
	return append([]byte{dtype, 1, 0, 0, wait, 0, byte(len(payload))}, payload...)
}

func cat2(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestParseDSICmds(t *testing.T) {
	stream := cat2(cmd(0x39, 0, 0xf0, 0x99, 0x16, 0x0c), cmd(0x05, 120, 0x11), cmd(0x39, 10, 0x28, 0, 0))
	got, ok := ParseDSICmds(stream)
	if !ok || len(got) != 3 {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	if got[0].Type != 0x39 || string(got[0].Payload) != "\xf0\x99\x16\x0c" || got[1].WaitMS != 120 || got[2].WaitMS != 10 {
		t.Errorf("parsed %+v", got)
	}
	// A record that runs past the end keeps what came before and says so.
	cut, ok := ParseDSICmds(stream[:len(stream)-2])
	if ok || len(cut) != 2 {
		t.Errorf("truncated: %+v ok=%v", cut, ok)
	}
}

func panelNode(t *testing.T) Panel {
	t.Helper()
	timing := &fdt.Node{Name: "timing@0", Props: map[string][]byte{
		"qcom,mdss-dsi-panel-width":      cells(720),
		"qcom,mdss-dsi-panel-height":     cells(1600),
		"qcom,mdss-dsi-h-front-porch":    cells(48),
		"qcom,mdss-dsi-h-pulse-width":    cells(4),
		"qcom,mdss-dsi-h-back-porch":     cells(48),
		"qcom,mdss-dsi-v-front-porch":    cells(1268),
		"qcom,mdss-dsi-v-pulse-width":    cells(4),
		"qcom,mdss-dsi-v-back-porch":     cells(32),
		"qcom,mdss-dsi-panel-framerate":  cells(60),
		"qcom,mdss-dsi-on-command":       cat2(cmd(0x39, 0, 0xf0, 0x99), cmd(0x05, 120, 0x11)),
		"qcom,mdss-dsi-off-command":      cmd(0x39, 10, 0x28, 0, 0),
		"qcom,mdss-dsi-on-command-state": []byte("dsi_lp_mode\x00"),
	}}
	for k := range timing.Props {
		timing.Keys = append(timing.Keys, k)
	}
	n := node("panel", map[string]string{
		"qcom,mdss-dsi-panel-type":           "dsi_video_mode\x00",
		"qcom,mdss-dsi-traffic-mode":         "non_burst_sync_event\x00",
		"qcom,mdss-dsi-pan-fps-update":       "dfps_immediate_porch_mode_vfp\x00",
		"qcom,mdss-dsi-bl-pmic-control-type": "bl_ctrl_dcs\x00",
	}, node("qcom,mdss-dsi-display-timings", nil, timing))
	for k, v := range map[string][]byte{
		"qcom,mdss-dsi-bpp":            cells(24),
		"qcom,dsi-supported-dfps-list": cells(60, 90),
		"qcom,mdss-dsi-reset-sequence": cells(0, 2, 1, 10),
		"qcom,mdss-dsi-bl-max-level":   cells(1637),
		"qcom,mdss-dsi-lane-0-state":   nil,
		"qcom,mdss-dsi-lane-1-state":   nil,
		"qcom,mdss-dsi-lane-2-state":   nil,
		"qcom,mdss-dsi-lane-3-state":   nil,
	} {
		n.Props[k] = v
		n.Keys = append(n.Keys, k)
	}
	return Panel{Name: "mipi_test_panel", MMW: 70, MMH: 156, Source: n}
}

func TestReadPanelDriverDerivesModesResetAndFlags(t *testing.T) {
	d, ok := ReadPanelDriver(panelNode(t))
	if !ok {
		t.Fatal("not read")
	}
	if len(d.Modes) != 2 {
		t.Fatalf("modes %+v", d.Modes)
	}
	// clock = htotal x vtotal x refresh: 820 x 2904 x 60.
	if m := d.Modes[0]; m.Clock != 142877 || m.htotal() != 820 || m.vtotal() != 2904 {
		t.Errorf("60 Hz mode %+v", m)
	}
	// 90 Hz at the same pixel clock: 142877000 / (820 x 90) = 1936 lines, so a 300-line front porch.
	if m := d.Modes[1]; m.Hz != 90 || m.Clock != 142877 || m.VFront != 300 || m.vtotal() != 1936 {
		t.Errorf("90 Hz mode %+v", m)
	}
	if d.Lanes != 4 || d.Format != "MIPI_DSI_FMT_RGB888" || !d.DCSBL || d.BLMax != 1637 {
		t.Errorf("lanes %d format %q dcsbl %v bl %d", d.Lanes, d.Format, d.DCSBL, d.BLMax)
	}
	if strings.Join(d.Flags, "|") != "MIPI_DSI_MODE_VIDEO|MIPI_DSI_MODE_LPM" {
		t.Errorf("flags %v (non-burst sync event is plain video; the lp command state adds LPM)", d.Flags)
	}
	if len(d.Reset) != 2 || d.Reset[0] != (ResetStep{0, 2}) || d.Reset[1] != (ResetStep{1, 10}) {
		t.Errorf("reset %+v", d.Reset)
	}
	if len(d.On) != 2 || len(d.Off) != 1 {
		t.Errorf("on %d off %d", len(d.On), len(d.Off))
	}
}

func TestPanelCSourceCarriesTheStockFacts(t *testing.T) {
	d, _ := ReadPanelDriver(panelNode(t))
	src := d.CSource()
	for _, want := range []string{
		"mipi_dsi_dcs_write_seq_multi(&dsi_ctx, 0xf0, 0x99);",
		"mipi_dsi_dcs_write_seq_multi(&dsi_ctx, 0x11);",
		"mipi_dsi_msleep(&dsi_ctx, 120);",
		"mipi_dsi_msleep(&dsi_ctx, 10);",
		".clock = 142877,",
		".vsync_start = 1600 + 1268,",
		".vsync_start = 1600 + 300,",
		"dsi->lanes = 4;",
		"dsi->mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_LPM;",
		"gpiod_set_value_cansleep(ctx->reset, 1);", // raw level 0 is asserted (active low)
		"usleep_range(2000, 3000);",
		"TODO",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("missing %q", want)
		}
	}
	if PanelFileName("mipi_mot_vid_tm_icnl9916c_hd_720_1600") != "panel-mipi-mot-vid-tm-icnl9916c-hd-720-1600.c" {
		t.Error("file name")
	}
}

func TestSeqCallPicksTheHelperByCommandType(t *testing.T) {
	for _, tt := range []struct {
		typ  byte
		want string
	}{
		{0x39, "mipi_dsi_dcs_write_seq_multi"}, {0x05, "mipi_dsi_dcs_write_seq_multi"}, {0x15, "mipi_dsi_dcs_write_seq_multi"},
		{0x29, "mipi_dsi_generic_write_seq_multi"}, {0x23, "mipi_dsi_generic_write_seq_multi"},
	} {
		if got := seqCall(DSICmd{Type: tt.typ, Payload: []byte{0x35, 0x00}}); !strings.Contains(got, tt.want+"(") {
			t.Errorf("type %#x -> %s", tt.typ, got)
		}
	}
}

const refDriver = `
static int on(struct mipi_dsi_device *dsi)
{
	mipi_dsi_dcs_write_seq_multi(&dsi_ctx, 0xf0, 0x99,
				     0x16, 0x0c); /* spans lines */
	mipi_dsi_generic_write_seq_multi(&dsi_ctx, 0x28);
	mipi_dsi_dcs_write_seq_multi(&dsi_ctx, 0x11);
}
static const struct drm_display_mode m[] = {{
	.clock = 142877,
	.vsync_start = 1600 + 1268,
}};
`

func TestReferenceSequencesAndPanelSection(t *testing.T) {
	seqs := ReferenceSequences(refDriver)
	if len(seqs) != 3 || string(seqs[0]) != "\xf0\x99\x16\x0c" || string(seqs[1]) != "\x28" {
		t.Fatalf("sequences %v", seqs)
	}
	d := PanelDriver{Name: "mine", Modes: []PanelMode{{Hz: 60, Clock: 142877, VFront: 1268}}, Format: "MIPI_DSI_FMT_RGB888", Lanes: 4,
		On:  []DSICmd{{Type: 0x39, Payload: []byte{0xf0, 0x99, 0x16, 0x0c}}, {Type: 0x05, Payload: []byte{0x11}}},
		Off: []DSICmd{{Type: 0x39, Payload: []byte{0x28, 0, 0}}}}
	other := PanelDriver{Name: "other", Modes: []PanelMode{{Hz: 60, Clock: 999, VFront: 1}}, Format: "MIPI_DSI_FMT_RGB888", Lanes: 4}
	out := PanelSection([]PanelDriver{d, other}, refDriver)
	for _, want := range []string{
		"| mine | 2 of 3 | 3 of 3 | 142877 ✓ | 1268 ✓ |", // the padded 0x28 matches only ignoring trailing zeros
		"| other | not in the reference |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if PanelSection(nil, "") != "" {
		t.Error("no panels, no section")
	}
}
