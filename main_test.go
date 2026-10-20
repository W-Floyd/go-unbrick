package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/hashcache"
)

// TestMain keeps tests off the user's real hash cache.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "unbrick-test")
	if err != nil {
		panic(err)
	}
	hashcache.Path = filepath.Join(dir, "hashes.jsonl")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
