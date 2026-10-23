package unixauth

// Recognizer adapts this package to pkg/analysis/recognize.Recognizer, mirroring
// cmd_recon.go's existing typeLabel/report unixauth handling exactly. Identify
// has no separate summary line today (cmd_recon.go's report comment: "the Type
// line above names it"), so Summary stays "".
type Recognizer struct{}

func (Recognizer) Name() string { return "unixauth" }

func (Recognizer) Version() int { return 1 }

func (Recognizer) Claims(name string, head []byte) bool {
	_, _, ok := Identify(name, head)
	return ok
}

func (Recognizer) Label(name string, head []byte) string {
	label, _, _ := Identify(name, head)
	return label
}

func (Recognizer) Summary(name string, head, data []byte) string { return "" }

func (Recognizer) Report(path, name string, head, data []byte) []string {
	_, lines, _ := Identify(name, head)
	return lines
}
