package bootimg

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestKernelConfig(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte("# comment\nCONFIG_ARCH_TCC=y\n"))
	w.Close()
	k := append([]byte("junkIKCFG_ST"), gz.Bytes()...)
	k = append(k, "IKCFG_ED"...)
	cfg, ok := KernelConfig(k)
	if !ok || !bytes.Contains(cfg, []byte("CONFIG_ARCH_TCC=y")) {
		t.Fatalf("got %q, %v", cfg, ok)
	}
	if _, ok := KernelConfig([]byte("no marker")); ok {
		t.Error("found a config without a marker")
	}
}
