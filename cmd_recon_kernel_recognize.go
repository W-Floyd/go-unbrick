package main

// kernelLabelRecognizer adapts kernelLabel (cmd_recon_kernel.go) to
// pkg/analysis/recognize.Recognizer. Report is nil: the full kernel report
// (reconKernel) is a separate dispatch path, keyed off
// filetype.ARM64Image/bootimg.IsZImage directly in cmd_recon.go's main
// switch, not part of this fallback chain -- see this migration's final
// report for why that's a deliberate split, not an omission.
type kernelLabelRecognizer struct{}

func (kernelLabelRecognizer) Name() string { return "kernel-label" }

func (kernelLabelRecognizer) Version() int { return 1 }

func (kernelLabelRecognizer) Claims(name string, head []byte) bool {
	_, ok := kernelLabel(name, head)
	return ok
}

func (kernelLabelRecognizer) Label(name string, head []byte) string {
	l, _ := kernelLabel(name, head)
	return l
}

// Summary is "": typeLabel's fallback chain has no summarize case for a
// kernel beyond the Label above.
func (kernelLabelRecognizer) Summary(name string, head, data []byte) string { return "" }

func (kernelLabelRecognizer) Report(path, name string, head, data []byte) []string { return nil }
