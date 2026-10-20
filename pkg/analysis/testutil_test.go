package analysis

import (
	"io"
	"os"
)

// captureStdout runs fn and returns what it printed.
func captureStdout(fn func() error) (string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	ferr := fn()
	os.Stdout = old
	w.Close()
	return <-done, ferr
}
