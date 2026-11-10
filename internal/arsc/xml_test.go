package arsc

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"strings"
	"testing"
)

func apkMember(t testing.TB, apk, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + apk)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	f, err := zr.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDecodeXML(t *testing.T) {
	s, err := DecodeXML(apkMember(t, "plain.apk", "AndroidManifest.xml"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`xmlns:android="http://schemas.android.com/apk/res/android"`,
		`package="com.example.compact"`,
		`android:minSdkVersion="34"`,
		`<application android:hasCode="false" />`,
		"</manifest>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in\n%s", want, s)
		}
	}
	d := xml.NewDecoder(strings.NewReader(s))
	for {
		if _, err := d.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("not well-formed: %v\n%s", err, s)
		}
	}
	// A truncated or corrupt member errors or renders partially; it never panics.
	b := apkMember(t, "plain.apk", "AndroidManifest.xml")
	for i := range b {
		DecodeXML(b[:i], nil)
		c := bytes.Clone(b)
		c[i] ^= 0xff
		DecodeXML(c, nil)
	}
}

func TestTableText(t *testing.T) {
	b := apkMember(t, "plain.apk", "resources.arsc")
	for i := range b {
		Parse(b[:i])
		c := bytes.Clone(b)
		c[i] ^= 0xff
		if tb, err := Parse(c); err == nil {
			tb.Text()
		}
	}
	tb, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	s := tb.Text()
	for _, want := range []string{
		"package com.example.compact (0x7f)\n",
		"array/list\n    - \"a\"\n    - \"b\"\n",
		"bool/flag = true\n",
		"color/tint = #ff112233\n",
		"dimen/corner = 62px\n",
		"dimen/radius = 24dp\n",
		"integer/answer = 42\n",
		`string/cutout = "M -35,0 L 35,0 L 35,80 L -35,80 Z"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}
