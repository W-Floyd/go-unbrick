// C interface over librapidarchive's ParallelGzipReader, for cgo. No C++
// exception crosses it: a failing call returns -1 (or NULL) and rg_error holds
// the message.
#ifndef RAPIDGZIP_SHIM_H
#define RAPIDGZIP_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rg_reader rg_reader;

// rg_open reads the compressed stream through the Go io.ReaderAt behind
// handle, size bytes long. parallelization 0 means one thread per core. On
// failure it returns NULL and, if err is non-NULL, a malloc'd message there.
rg_reader* rg_open(uintptr_t handle, uint64_t size, size_t parallelization, uint64_t chunk_size, char** err);
void rg_close(rg_reader* r);
const char* rg_error(rg_reader* r);

// rg_read returns the bytes read, 0 at end of stream, -1 on error.
long long rg_read(rg_reader* r, char* buf, size_t n);
// rg_seek takes SEEK_SET/SEEK_CUR/SEEK_END; returns the new offset or -1.
long long rg_seek(rg_reader* r, long long offset, int whence);
long long rg_tell(rg_reader* r);
// rg_size returns the decompressed size, or -1 while it is not yet known (the
// whole stream has not been seen and no index was imported).
long long rg_size(rg_reader* r);

// rg_export_index writes the seek index, in indexed_gzip format, to the Go
// io.Writer behind writer. rg_import_index reads one from the io.ReaderAt
// behind handle. Both return 0 or -1.
int rg_export_index(rg_reader* r, uintptr_t writer);
int rg_import_index(rg_reader* r, uintptr_t handle, uint64_t size);

#ifdef __cplusplus
}
#endif

#endif
