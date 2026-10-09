package rapidgzip

// The C++ side calls back into Go for every read of the compressed stream and
// every write of an exported index. A file with //export may only declare in
// its preamble, so these live apart from the bindings.

/*
#include <stddef.h>
#include <stdint.h>
*/
import "C"

import (
	"io"
	"runtime/cgo"
	"unsafe"
)

//export goReadAt
func goReadAt(h C.uintptr_t, buf *C.char, n C.size_t, off C.longlong) C.longlong {
	ra := cgo.Handle(h).Value().(io.ReaderAt)
	p := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n))
	got, err := ra.ReadAt(p, int64(off))
	if err != nil && err != io.EOF {
		return -1
	}
	return C.longlong(got)
}

//export goWrite
func goWrite(h C.uintptr_t, buf unsafe.Pointer, n C.size_t) C.int {
	w := cgo.Handle(h).Value().(io.Writer)
	if _, err := w.Write(unsafe.Slice((*byte)(buf), int(n))); err != nil {
		return 1
	}
	return 0
}
