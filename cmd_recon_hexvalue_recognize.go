package main

import "encoding/hex"

// hexValueRecognizer adapts hexValue/hexValueLabel/datStatus (cmd_recon_secrets.go)
// to pkg/analysis/recognize.Recognizer, the same shape as
// internal/androidkeys/recognize.go.
type hexValueRecognizer struct{}

func (hexValueRecognizer) Name() string { return "hex-value" }

func (hexValueRecognizer) Claims(name string, head []byte) bool {
	_, ok := hexValue(head)
	return ok
}

func (hexValueRecognizer) Label(name string, head []byte) string {
	b, _ := hexValue(head)
	return hexValueLabel(b)
}

// Summary is "": typeLabel's fallback chain has no summarize case for a hex
// key/IV file, only the Label above.
func (hexValueRecognizer) Summary(name string, head, data []byte) string { return "" }

func (hexValueRecognizer) Report(path, name string, head, data []byte) []string {
	b, ok := hexValue(head)
	if !ok {
		return nil
	}
	return []string{datStatus(hex.EncodeToString(b))}
}
