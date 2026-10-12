package port

import (
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/fdt"
)

// DSICmd is one command of a stock panel command stream: Qualcomm's
// "dtype last vc ack wait dlen(2) payload" records.
type DSICmd struct {
	Type    byte
	WaitMS  int
	Payload []byte
}

// ParseDSICmds splits a stock command stream into commands. A stream that does
// not parse cleanly (a record running past the end) yields what came before
// the break, and ok is false.
func ParseDSICmds(b []byte) (cmds []DSICmd, ok bool) {
	for i := 0; i < len(b); {
		if i+7 > len(b) {
			return cmds, false
		}
		n := int(binary.BigEndian.Uint16(b[i+5:]))
		if i+7+n > len(b) {
			return cmds, false
		}
		cmds = append(cmds, DSICmd{Type: b[i], WaitMS: int(b[i+4]), Payload: append([]byte(nil), b[i+7:i+7+n]...)})
		i += 7 + n
	}
	return cmds, true
}

// PanelMode is one display mode, in the kernel's terms.
type PanelMode struct {
	Hz                                                             int
	Clock                                                          int // kHz
	HDisplay, HFront, HSync, HBack, VDisplay, VFront, VSync, VBack int
	Note                                                           string
}

func (m PanelMode) htotal() int { return m.HDisplay + m.HFront + m.HSync + m.HBack }
func (m PanelMode) vtotal() int { return m.VDisplay + m.VFront + m.VSync + m.VBack }

// ResetStep is one step of a stock reset sequence: hold the raw level for the
// delay.
type ResetStep struct{ Level, DelayMS int }

// PanelDriver is what the stock panel node says a panel driver must do.
type PanelDriver struct {
	Name     string
	Modes    []PanelMode
	MMW, MMH uint32
	Lanes    int
	Format   string   // MIPI_DSI_FMT_*
	Flags    []string // MIPI_DSI_MODE_*
	Reset    []ResetStep
	BLMax    int
	DCSBL    bool // brightness is set by DCS command
	On, Off  []DSICmd
	Notes    []string // what could not be read, or was assumed
}

var laneState = regexp.MustCompile(`^qcom,mdss-dsi-lane-(\d)-state$`)

func u32(n *fdt.Node, prop string) (int, bool) {
	if c := n.U32s(prop); len(c) > 0 {
		return int(c[0]), true
	}
	return 0, false
}

// ReadPanelDriver reads a stock DSI panel node (and its first display timing)
// into the facts a driver needs. The pixel clock is htotal x vtotal x refresh;
// each further refresh rate the node lists for dynamic fps is the same clock
// with the vertical front porch stretched or cut to fit.
func ReadPanelDriver(pn Panel) (PanelDriver, bool) {
	n := pn.Source
	if n == nil {
		return PanelDriver{}, false
	}
	d := PanelDriver{Name: pn.Name, MMW: pn.MMW, MMH: pn.MMH}

	timings := childNamed(n, "qcom,mdss-dsi-display-timings")
	if timings == nil || len(timings.Children) == 0 {
		return d, false
	}
	t := timings.Children[0]
	var m PanelMode
	m.HDisplay, _ = u32(t, "qcom,mdss-dsi-panel-width")
	m.VDisplay, _ = u32(t, "qcom,mdss-dsi-panel-height")
	m.HFront, _ = u32(t, "qcom,mdss-dsi-h-front-porch")
	m.HSync, _ = u32(t, "qcom,mdss-dsi-h-pulse-width")
	m.HBack, _ = u32(t, "qcom,mdss-dsi-h-back-porch")
	m.VFront, _ = u32(t, "qcom,mdss-dsi-v-front-porch")
	m.VSync, _ = u32(t, "qcom,mdss-dsi-v-pulse-width")
	m.VBack, _ = u32(t, "qcom,mdss-dsi-v-back-porch")
	m.Hz, _ = u32(t, "qcom,mdss-dsi-panel-framerate")
	if m.HDisplay == 0 || m.VDisplay == 0 || m.Hz == 0 {
		return d, false
	}
	m.Clock = int(math.Round(float64(m.htotal()) * float64(m.vtotal()) * float64(m.Hz) / 1000))
	d.Modes = append(d.Modes, m)

	if mode, _ := n.Str("qcom,mdss-dsi-pan-fps-update"); strings.Contains(mode, "vfp") {
		for _, hz := range n.U32s("qcom,dsi-supported-dfps-list") {
			if int(hz) == m.Hz || hz == 0 {
				continue
			}
			alt := m
			alt.Hz = int(hz)
			total := int(math.Round(float64(m.Clock) * 1000 / (float64(m.htotal()) * float64(hz))))
			alt.VFront = total - m.VDisplay - m.VSync - m.VBack
			alt.Note = fmt.Sprintf("the %d Hz mode with the vertical front porch changed to fit the same pixel clock", m.Hz)
			d.Modes = append(d.Modes, alt)
		}
	}

	for _, k := range n.Keys {
		if laneState.MatchString(k) {
			d.Lanes++
		}
	}
	if bpp, ok := u32(n, "qcom,mdss-dsi-bpp"); ok {
		switch bpp {
		case 24:
			d.Format = "MIPI_DSI_FMT_RGB888"
		case 18:
			d.Format = "MIPI_DSI_FMT_RGB666"
		case 16:
			d.Format = "MIPI_DSI_FMT_RGB565"
		default:
			d.Notes = append(d.Notes, fmt.Sprintf("pixel depth %d bpp is not a DSI format this tool maps", bpp))
		}
	}

	switch pt, _ := n.Str("qcom,mdss-dsi-panel-type"); pt {
	case "dsi_video_mode":
		d.Flags = append(d.Flags, "MIPI_DSI_MODE_VIDEO")
		switch tm, _ := n.Str("qcom,mdss-dsi-traffic-mode"); tm {
		case "burst_mode":
			d.Flags = append(d.Flags, "MIPI_DSI_MODE_VIDEO_BURST")
		case "non_burst_sync_pulse":
			d.Flags = append(d.Flags, "MIPI_DSI_MODE_VIDEO_SYNC_PULSE")
		case "non_burst_sync_event", "":
		default:
			d.Notes = append(d.Notes, "traffic mode "+tm+" is not mapped")
		}
	default:
		d.Notes = append(d.Notes, "panel type "+pt+": a command-mode panel needs a different driver shape")
	}
	if st, _ := t.Str("qcom,mdss-dsi-on-command-state"); st == "dsi_lp_mode" {
		d.Flags = append(d.Flags, "MIPI_DSI_MODE_LPM")
	}

	if seq := n.U32s("qcom,mdss-dsi-reset-sequence"); len(seq)%2 == 0 {
		for i := 0; i+1 < len(seq); i += 2 {
			d.Reset = append(d.Reset, ResetStep{Level: int(seq[i]), DelayMS: int(seq[i+1])})
		}
	}
	d.BLMax, _ = u32(n, "qcom,mdss-dsi-bl-max-level")
	ct, _ := n.Str("qcom,mdss-dsi-bl-pmic-control-type")
	d.DCSBL = ct == "bl_ctrl_dcs"

	var ok bool
	if raw, has := t.Props["qcom,mdss-dsi-on-command"]; has {
		if d.On, ok = ParseDSICmds(raw); !ok {
			d.Notes = append(d.Notes, "the on-command stream did not parse to its end")
		}
	}
	if raw, has := t.Props["qcom,mdss-dsi-off-command"]; has {
		if d.Off, ok = ParseDSICmds(raw); !ok {
			d.Notes = append(d.Notes, "the off-command stream did not parse to its end")
		}
	}
	if len(timings.Children) > 1 {
		d.Notes = append(d.Notes, fmt.Sprintf("the node lists %d display timings; only the first is read", len(timings.Children)))
	}
	return d, true
}

// seqCall renders one stock command as the kernel helper that sends it. A DCS
// type (0x05, 0x15, 0x39) is a DCS write whose first payload byte is the
// command; the generic types (0x03, 0x13, 0x23, 0x29) are generic writes.
func seqCall(c DSICmd) string {
	var bytes []string
	for _, b := range c.Payload {
		bytes = append(bytes, fmt.Sprintf("0x%02x", b))
	}
	helper := "mipi_dsi_generic_write_seq_multi"
	switch c.Type {
	case 0x05, 0x15, 0x39:
		helper = "mipi_dsi_dcs_write_seq_multi"
	}
	return fmt.Sprintf("\t%s(&dsi_ctx, %s);", helper, strings.Join(bytes, ", "))
}

func writeSeq(b *strings.Builder, cmds []DSICmd) {
	for _, c := range cmds {
		fmt.Fprintln(b, seqCall(c))
		if c.WaitMS > 0 {
			fmt.Fprintf(b, "\tmipi_dsi_msleep(&dsi_ctx, %d);\n", c.WaitMS)
		}
	}
}

// PanelFileName is the driver draft's file name for a stock panel name.
func PanelFileName(name string) string {
	return "panel-" + strings.ToLower(strings.ReplaceAll(name, "_", "-")) + ".c"
}

// CSource drafts the panel driver. It carries what the stock node settles (the
// modes, the reset timing, the init and off sequences, the lanes, the format
// and mode flags) in the shape of an upstream DSI panel driver, with the rest
// as TODOs. It is a draft, not a compiled driver.
func (d PanelDriver) CSource() string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	id := strings.ReplaceAll(strings.ToLower(d.Name), "-", "_")
	w("// SPDX-License-Identifier: GPL-2.0-only")
	w("// Draft DSI panel driver from the stock panel node %q.", d.Name)
	w("// Generated by unbrick port; it has not been compiled. Lines marked TODO need a decision.")
	w("")
	w("#include <linux/delay.h>")
	w("#include <linux/gpio/consumer.h>")
	w("#include <linux/module.h>")
	w("#include <linux/of.h>")
	w("#include <linux/regulator/consumer.h>")
	w("")
	w("#include <drm/drm_mipi_dsi.h>")
	w("#include <drm/drm_modes.h>")
	w("#include <drm/drm_panel.h>")
	w("")
	w("struct %s {", id)
	w("\tstruct drm_panel panel;")
	w("\tstruct mipi_dsi_device *dsi;")
	w("\tstruct gpio_desc *reset;")
	w("\tstruct regulator_bulk_data *supplies; /* TODO: the stock node's supplies */")
	w("};")
	w("")
	w("static inline struct %s *to_%s(struct drm_panel *panel)", id, id)
	w("{")
	w("\treturn container_of(panel, struct %s, panel);", id)
	w("}")
	w("")

	w("/*")
	w(" * Stock reset sequence, as (raw level, ms) steps: %s.", resetText(d.Reset))
	w(" * The logical values below assume reset-gpios is GPIO_ACTIVE_LOW, so a raw")
	w(" * level of 0 is asserted. TODO: confirm the polarity on the board.")
	w(" */")
	w("static void %s_reset(struct %s *ctx)", id, id)
	w("{")
	for _, s := range d.Reset {
		w("\tgpiod_set_value_cansleep(ctx->reset, %d);", 1-boolInt(s.Level != 0))
		if s.DelayMS > 0 {
			w("\tusleep_range(%d, %d);", s.DelayMS*1000, s.DelayMS*1000+1000)
		}
	}
	if len(d.Reset) == 0 {
		w("\t/* TODO: the stock node has no reset sequence */")
	}
	w("}")
	w("")

	w("static int %s_on(struct %s *ctx)", id, id)
	w("{")
	w("\tstruct mipi_dsi_multi_context dsi_ctx = { .dsi = ctx->dsi };")
	w("")
	writeSeq(&b, d.On)
	if len(d.On) == 0 {
		w("\t/* TODO: the stock node has no on-command */")
	}
	w("")
	w("\treturn dsi_ctx.accum_err;")
	w("}")
	w("")
	w("static int %s_off(struct %s *ctx)", id, id)
	w("{")
	w("\tstruct mipi_dsi_multi_context dsi_ctx = { .dsi = ctx->dsi };")
	w("")
	writeSeq(&b, d.Off)
	if len(d.Off) == 0 {
		w("\t/* TODO: the stock node has no off-command */")
	}
	w("")
	w("\treturn dsi_ctx.accum_err;")
	w("}")
	w("")

	w("static int %s_prepare(struct drm_panel *panel)", id)
	w("{")
	w("\tstruct %s *ctx = to_%s(panel);", id, id)
	w("\tint ret;")
	w("")
	w("\t/* TODO: enable the supplies, with the waits the stock node gives */")
	w("\t%s_reset(ctx);", id)
	w("\tret = %s_on(ctx);", id)
	w("\tif (ret < 0) {")
	w("\t\tgpiod_set_value_cansleep(ctx->reset, 1);")
	w("\t\treturn ret;")
	w("\t}")
	w("\treturn 0;")
	w("}")
	w("")
	w("static int %s_unprepare(struct drm_panel *panel)", id)
	w("{")
	w("\tstruct %s *ctx = to_%s(panel);", id, id)
	w("")
	w("\t%s_off(ctx);", id)
	w("\tgpiod_set_value_cansleep(ctx->reset, 1);")
	w("\t/* TODO: disable the supplies */")
	w("\treturn 0;")
	w("}")
	w("")

	w("static const struct drm_display_mode %s_modes[] = {", id)
	for _, m := range d.Modes {
		w("\t{")
		if m.Note != "" {
			w("\t\t/* %d Hz: %s */", m.Hz, m.Note)
		} else {
			w("\t\t/* %d Hz */", m.Hz)
		}
		w("\t\t.clock = %d,", m.Clock)
		w("\t\t.hdisplay = %d,", m.HDisplay)
		w("\t\t.hsync_start = %d + %d,", m.HDisplay, m.HFront)
		w("\t\t.hsync_end = %d + %d + %d,", m.HDisplay, m.HFront, m.HSync)
		w("\t\t.htotal = %d + %d + %d + %d,", m.HDisplay, m.HFront, m.HSync, m.HBack)
		w("\t\t.vdisplay = %d,", m.VDisplay)
		w("\t\t.vsync_start = %d + %d,", m.VDisplay, m.VFront)
		w("\t\t.vsync_end = %d + %d + %d,", m.VDisplay, m.VFront, m.VSync)
		w("\t\t.vtotal = %d + %d + %d + %d,", m.VDisplay, m.VFront, m.VSync, m.VBack)
		w("\t\t.width_mm = %d, /* TODO: the stock node's size ran large on one device */", d.MMW)
		w("\t\t.height_mm = %d,", d.MMH)
		w("\t\t.type = DRM_MODE_TYPE_DRIVER%s,", preferred(m, d.Modes))
		w("\t},")
	}
	w("};")
	w("")
	w("static int %s_get_modes(struct drm_panel *panel, struct drm_connector *connector)", id)
	w("{")
	w("\tint i, n = 0;")
	w("")
	w("\tfor (i = 0; i < ARRAY_SIZE(%s_modes); i++) {", id)
	w("\t\tstruct drm_display_mode *mode = drm_mode_duplicate(connector->dev, &%s_modes[i]);", id)
	w("")
	w("\t\tif (!mode)")
	w("\t\t\treturn n;")
	w("\t\tdrm_mode_probed_add(connector, mode);")
	w("\t\tn++;")
	w("\t}")
	w("\treturn n;")
	w("}")
	w("")
	w("static const struct drm_panel_funcs %s_funcs = {", id)
	w("\t.prepare = %s_prepare,", id)
	w("\t.unprepare = %s_unprepare,", id)
	w("\t.get_modes = %s_get_modes,", id)
	w("};")
	w("")
	if d.DCSBL {
		w("/* Brightness is a DCS command in the stock node; its maximum level is %d. TODO: a backlight device. */", d.BLMax)
		w("")
	}
	w("static int %s_probe(struct mipi_dsi_device *dsi)", id)
	w("{")
	w("\tstruct device *dev = &dsi->dev;")
	w("\tstruct %s *ctx;", id)
	w("")
	w("\tctx = devm_kzalloc(dev, sizeof(*ctx), GFP_KERNEL);")
	w("\tif (!ctx)")
	w("\t\treturn -ENOMEM;")
	w("")
	w("\tctx->reset = devm_gpiod_get(dev, \"reset\", GPIOD_OUT_HIGH);")
	w("\tif (IS_ERR(ctx->reset))")
	w("\t\treturn dev_err_probe(dev, PTR_ERR(ctx->reset), \"Failed to get reset-gpios\\n\");")
	w("")
	w("\tctx->dsi = dsi;")
	w("\tmipi_dsi_set_drvdata(dsi, ctx);")
	lanes := "/* TODO: no lane states in the stock node */ 4"
	if d.Lanes > 0 {
		lanes = fmt.Sprint(d.Lanes)
	}
	w("\tdsi->lanes = %s;", lanes)
	format := "/* TODO */ MIPI_DSI_FMT_RGB888"
	if d.Format != "" {
		format = d.Format
	}
	w("\tdsi->format = %s;", format)
	flags := "0 /* TODO */"
	if len(d.Flags) > 0 {
		flags = strings.Join(d.Flags, " | ")
	}
	w("\tdsi->mode_flags = %s;", flags)
	w("")
	w("\tdrm_panel_init(&ctx->panel, dev, &%s_funcs, DRM_MODE_CONNECTOR_DSI);", id)
	w("\tdrm_panel_add(&ctx->panel);")
	w("\treturn mipi_dsi_attach(dsi);")
	w("}")
	w("")
	w("static const struct of_device_id %s_of_match[] = {", id)
	w("\t{ .compatible = \"TODO,%s\" }, /* TODO: a binding for this panel */", strings.ReplaceAll(id, "_", "-"))
	w("\t{ /* sentinel */ }")
	w("};")
	w("MODULE_DEVICE_TABLE(of, %s_of_match);", id)
	w("")
	w("static struct mipi_dsi_driver %s_driver = {", id)
	w("\t.probe = %s_probe,", id)
	w("\t.driver = {")
	w("\t\t.name = \"panel-%s\",", strings.ReplaceAll(id, "_", "-"))
	w("\t\t.of_match_table = %s_of_match,", id)
	w("\t},")
	w("};")
	w("module_mipi_dsi_driver(%s_driver);", id)
	w("")
	w("MODULE_DESCRIPTION(\"Draft DSI panel driver for %s\");", d.Name)
	w("MODULE_LICENSE(\"GPL\");")
	return b.String()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func resetText(rs []ResetStep) string {
	var s []string
	for _, r := range rs {
		s = append(s, fmt.Sprintf("(%d, %d)", r.Level, r.DelayMS))
	}
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

// preferred marks the base mode (the first) as the boot default.
func preferred(m PanelMode, all []PanelMode) string {
	if len(all) > 0 && m.Hz == all[0].Hz && m.Note == "" {
		return " | DRM_MODE_TYPE_PREFERRED"
	}
	return ""
}

// PanelDrivers reads a driver draft for every panel the board references.
func PanelDrivers(p Package) []PanelDriver {
	var out []PanelDriver
	for _, pn := range p.DT.Panels {
		if d, ok := ReadPanelDriver(pn); ok {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
