package pemfile

// Recognizer adapts this package to pkg/analysis/recognize.Recognizer, mirroring
// cmd_recon.go's existing typeLabel/summarize/report PEM handling exactly.
type Recognizer struct{}

func (Recognizer) Name() string { return "pemfile" }

func (Recognizer) Claims(name string, head []byte) bool { return Is(head) }

func (Recognizer) Label(name string, head []byte) string {
	blocks, _ := Parse(head)
	return Label(blocks)
}

func (Recognizer) Summary(name string, head, data []byte) string {
	if blocks, ok := Parse(head); ok && len(blocks) == 1 {
		return " — " + blocks[0].Detail
	}
	return ""
}

func (Recognizer) Report(path, name string, head, data []byte) []string {
	blocks, ok := Parse(head)
	if !ok {
		return nil
	}
	var lines []string
	for _, b := range blocks {
		lines = append(lines, b.Detail)
		for _, l := range b.Lines {
			lines = append(lines, "  "+l)
		}
	}
	return lines
}
