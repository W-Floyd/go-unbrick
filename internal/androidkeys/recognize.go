package androidkeys

// Recognizer adapts this package to pkg/analysis/recognize.Recognizer: a
// template every other recognizer in this migration follows the same shape
// of. Keep the actual parsing in the package's own functions (Is/Parse/
// Summary/Lines here); this file is only the thin adapter, so bumping
// cache.Versions["androidkeys"] is the one thing a future change to those
// functions' behavior requires remembering to do.
type Recognizer struct{}

func (Recognizer) Name() string { return "androidkeys" }

func (Recognizer) Claims(name string, head []byte) bool { return Is(head) }

func (Recognizer) Label(name string, head []byte) string { return "Android recovery keys" }

func (Recognizer) Summary(name string, head, data []byte) string {
	if keys, ok := Parse(head); ok {
		return Summary(keys)
	}
	return ""
}

func (Recognizer) Report(path, name string, head, data []byte) []string {
	keys, ok := Parse(head)
	if !ok {
		return nil
	}
	return Lines(keys)
}
