// Package otameta decodes the small descriptive members of an AOSP A/B OTA
// package: the metadata sheet (text and protobuf), the APEX manifest, the
// verity care map and the signer certificate. The protobufs carry no magic, so
// they are known by the fixed names AOSP gives them and confirmed by parsing.
package otameta

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// Metadata is META-INF/com/android/metadata.pb (OtaMetadata in AOSP's
// ota_metadata.proto).
type Metadata struct {
	Type            string // AB, BLOCK, BRICK
	Wipe            bool
	Downgrade       bool
	SPLDowngrade    bool
	RetrofitDynamic bool
	RequiredCache   int64
	Pre, Post       DeviceState
}

// DeviceState is a pre- or postcondition of the update.
type DeviceState struct {
	Devices       []string
	Builds        []string
	Incremental   string
	Timestamp     int64
	SDKLevel      string
	SecurityPatch string
}

var otaTypes = map[uint64]string{0: "UNKNOWN", 1: "AB", 2: "BLOCK", 3: "BRICK"}

// ParseMetadata decodes metadata.pb.
func ParseMetadata(b []byte) (*Metadata, error) {
	m := &Metadata{}
	err := fields(b, func(num protowire.Number, v value) error {
		switch num {
		case 1:
			m.Type = otaTypes[v.u]
		case 2:
			m.Wipe = v.u != 0
		case 3:
			m.Downgrade = v.u != 0
		case 5, 6:
			s, err := parseDeviceState(v.b)
			if err != nil {
				return err
			}
			if num == 5 {
				m.Pre = s
			} else {
				m.Post = s
			}
		case 7:
			m.RetrofitDynamic = v.u != 0
		case 8:
			m.RequiredCache = int64(v.u)
		case 9:
			m.SPLDowngrade = v.u != 0
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if m.Type == "" || len(m.Post.Builds) == 0 {
		return nil, errors.New("otameta: not an OtaMetadata")
	}
	return m, nil
}

func parseDeviceState(b []byte) (DeviceState, error) {
	var s DeviceState
	err := fields(b, func(num protowire.Number, v value) error {
		switch num {
		case 1:
			s.Devices = append(s.Devices, string(v.b))
		case 2:
			s.Builds = append(s.Builds, string(v.b))
		case 3:
			s.Incremental = string(v.b)
		case 4:
			s.Timestamp = int64(v.u)
		case 5:
			s.SDKLevel = string(v.b)
		case 6:
			s.SecurityPatch = string(v.b)
		}
		return nil
	})
	return s, err
}

// Apex is one entry of apex_info.pb (ApexMetadata in update_metadata.proto).
type Apex struct {
	Name             string
	Version          int64
	Compressed       bool
	DecompressedSize int64
}

// ParseApexInfo decodes apex_info.pb.
func ParseApexInfo(b []byte) ([]Apex, error) {
	var out []Apex
	err := fields(b, func(num protowire.Number, v value) error {
		if num != 1 {
			return nil
		}
		var a Apex
		if err := fields(v.b, func(num protowire.Number, v value) error {
			switch num {
			case 1:
				a.Name = string(v.b)
			case 2:
				a.Version = int64(v.u)
			case 3:
				a.Compressed = v.u != 0
			case 4:
				a.DecompressedSize = int64(v.u)
			}
			return nil
		}); err != nil {
			return err
		}
		if a.Name == "" {
			return errors.New("otameta: APEX entry without a name")
		}
		out = append(out, a)
		return nil
	})
	if err == nil && len(out) == 0 {
		err = errors.New("otameta: no APEX entries")
	}
	return out, err
}

// CarePartition is one entry of care_map.pb: the blocks dm-verity checks and the
// build fingerprint of the image they belong to.
type CarePartition struct {
	Name        string
	Ranges      string
	IDProp      string // the property naming the fingerprint, e.g. ro.system.build.fingerprint
	Fingerprint string
}

// ParseCareMap decodes care_map.pb (CareMap in system/extras verity).
func ParseCareMap(b []byte) ([]CarePartition, error) {
	var out []CarePartition
	err := fields(b, func(num protowire.Number, v value) error {
		if num != 1 {
			return nil
		}
		var p CarePartition
		if err := fields(v.b, func(num protowire.Number, v value) error {
			switch num {
			case 1:
				p.Name = string(v.b)
			case 2:
				p.Ranges = string(v.b)
			case 3:
				p.IDProp = string(v.b)
			case 4:
				p.Fingerprint = string(v.b)
			}
			return nil
		}); err != nil {
			return err
		}
		if p.Name == "" {
			return errors.New("otameta: care map entry without a name")
		}
		out = append(out, p)
		return nil
	})
	if err == nil && len(out) == 0 {
		err = errors.New("otameta: empty care map")
	}
	return out, err
}

// IsTextMetadata reports whether data is the plain-text metadata sheet.
func IsTextMetadata(data []byte) bool {
	if len(data) == 0 || len(data) > 1<<16 || bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	s := string(data)
	return strings.Contains(s, "post-build=") &&
		(strings.Contains(s, "pre-device=") || strings.Contains(s, "ota-type="))
}

// ParseTextMetadata splits the sheet into its key=value pairs.
func ParseTextMetadata(data []byte) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && v != "" {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// Certs returns the certificates in a PEM file, or nil if it holds none.
func Certs(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return out
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

// Describe labels one of the members this package knows, with a one-line
// summary; ok is false for anything else. base is the member's base name.
func Describe(base string, data []byte) (label, detail string, ok bool) {
	switch base {
	case "metadata.pb":
		m, err := ParseMetadata(data)
		if err != nil {
			return "", "", false
		}
		return "OTA metadata (protobuf)", describeMetadata(m.Type, first(m.Pre.Devices), m.Post.Incremental, m.Post.SDKLevel, m.Wipe, m.Downgrade), true
	case "apex_info.pb":
		if len(data) == 0 { // written empty when the build lists no APEXes
			return "APEX manifest", "empty: no modules listed", true
		}
		apexes, err := ParseApexInfo(data)
		if err != nil {
			return "", "", false
		}
		n := 0
		for _, a := range apexes {
			if a.Compressed {
				n++
			}
		}
		return "APEX manifest", fmt.Sprintf("%d modules, %d compressed", len(apexes), n), true
	case "care_map.pb":
		parts, err := ParseCareMap(data)
		if err != nil {
			return "", "", false
		}
		names := make([]string, len(parts))
		for i, p := range parts {
			names[i] = p.Name
		}
		return "verity care map", strings.Join(names, ", "), true
	}
	if IsTextMetadata(data) {
		m := ParseTextMetadata(data)
		return "OTA metadata", describeMetadata(m["ota-type"], m["pre-device"], m["post-build-incremental"], m["post-sdk-level"],
			m["ota-wipe"] == "yes", m["ota-downgrade"] == "yes"), true
	}
	if certs := Certs(data); len(certs) > 0 {
		c := certs[0]
		return "X.509 cert", fmt.Sprintf("%s, %s, expires %s", subjectName(c), c.SignatureAlgorithm, c.NotAfter.Format("2006-01-02")), true
	}
	return "", "", false
}

func describeMetadata(typ, device, incremental, sdk string, wipe, downgrade bool) string {
	var parts []string
	for _, s := range []string{typ, device, incremental} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	if sdk != "" {
		parts = append(parts, "SDK "+sdk)
	}
	if wipe {
		parts = append(parts, "wipes data")
	}
	if downgrade {
		parts = append(parts, "downgrade")
	}
	return strings.Join(parts, ", ")
}

func subjectName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// value is one decoded field: a varint in u, or length-delimited bytes in b.
type value struct {
	u uint64
	b []byte
}

// fields walks a protobuf message, handing each varint or length-delimited
// field to fn; fixed-width fields are skipped, malformed input is an error.
func fields(b []byte, fn func(protowire.Number, value) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		var v value
		switch typ {
		case protowire.VarintType:
			v.u, n = protowire.ConsumeVarint(b)
		case protowire.BytesType:
			v.b, n = protowire.ConsumeBytes(b)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n >= 0 {
				b = b[n:]
				continue
			}
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if err := fn(num, v); err != nil {
			return err
		}
	}
	return nil
}
