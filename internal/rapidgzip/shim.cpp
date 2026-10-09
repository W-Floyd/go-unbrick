#include "shim.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

#include <filereader/FileReader.hpp>
#include <rapidgzip/ParallelGzipReader.hpp>

#include "_cgo_export.h"

namespace
{
// GoFileReader reads through a Go io.ReaderAt. Each clone keeps its own
// position over the same handle, which ReadAt makes safe to share.
class GoFileReader final :
    public rapidgzip::FileReader
{
public:
    GoFileReader( uintptr_t handle,
                  size_t    size ) :
        m_handle( handle ),
        m_size( size )
    {}

    void
    close() override
    {
        m_closed = true;
    }

    [[nodiscard]] bool
    closed() const override
    {
        return m_closed;
    }

    [[nodiscard]] bool
    eof() const override
    {
        return m_position >= m_size;
    }

    [[nodiscard]] bool
    fail() const override
    {
        return false;
    }

    [[nodiscard]] int
    fileno() const override
    {
        throw std::logic_error( "a Go reader has no file descriptor" );
    }

    [[nodiscard]] bool
    seekable() const override
    {
        return true;
    }

    [[nodiscard]] size_t
    read( char*  buffer,
          size_t nMaxBytesToRead ) override
    {
        if ( m_position >= m_size ) {
            return 0;
        }
        const auto n = std::min( nMaxBytesToRead, m_size - m_position );
        const auto got = goReadAt( m_handle, buffer, n, static_cast<long long>( m_position ) );
        if ( got < 0 ) {
            throw std::runtime_error( "reading the compressed stream failed" );
        }
        m_position += static_cast<size_t>( got );
        return static_cast<size_t>( got );
    }

    size_t
    seek( long long int offset,
          int           origin = SEEK_SET ) override
    {
        long long int base = 0;
        if ( origin == SEEK_CUR ) {
            base = static_cast<long long int>( m_position );
        } else if ( origin == SEEK_END ) {
            base = static_cast<long long int>( m_size );
        }
        const auto target = base + offset;
        if ( target < 0 ) {
            throw std::invalid_argument( "seek before the start of the stream" );
        }
        m_position = std::min( static_cast<size_t>( target ), m_size );
        return m_position;
    }

    [[nodiscard]] std::optional<size_t>
    size() const override
    {
        return m_size;
    }

    [[nodiscard]] size_t
    tell() const override
    {
        return m_position;
    }

    void
    clearerr() override
    {}

protected:
    [[nodiscard]] rapidgzip::UniqueFileReader
    cloneRaw() const override
    {
        auto copy = std::make_unique<GoFileReader>( m_handle, m_size );
        copy->m_position = m_position;
        return copy;
    }

private:
    uintptr_t m_handle;
    size_t m_size;
    size_t m_position{ 0 };
    bool m_closed{ false };
};

char*
duplicate( const std::string& s )
{
    auto* out = static_cast<char*>( std::malloc( s.size() + 1 ) );
    if ( out != nullptr ) {
        std::memcpy( out, s.c_str(), s.size() + 1 );
    }
    return out;
}
}  // namespace

struct rg_reader
{
    std::unique_ptr<rapidgzip::ParallelGzipReader<> > reader;
    std::string error;
};

namespace
{
template<typename F>
long long
guarded( rg_reader* r,
         F&&        f )
{
    try {
        return f();
    } catch ( const std::exception& e ) {
        r->error = e.what();
    } catch ( ... ) {
        r->error = "unknown error";
    }
    return -1;
}
}  // namespace

extern "C" {

rg_reader*
rg_open( uintptr_t handle,
         uint64_t  size,
         size_t    parallelization,
         uint64_t  chunk_size,
         char**    err )
{
    try {
        auto r = std::make_unique<rg_reader>();
        r->reader = std::make_unique<rapidgzip::ParallelGzipReader<> >(
            std::make_unique<GoFileReader>( handle, static_cast<size_t>( size ) ),
            parallelization,
            chunk_size == 0 ? 4ULL * 1024 * 1024 : chunk_size );
        return r.release();
    } catch ( const std::exception& e ) {
        if ( err != nullptr ) {
            *err = duplicate( e.what() );
        }
    } catch ( ... ) {
        if ( err != nullptr ) {
            *err = duplicate( "unknown error" );
        }
    }
    return nullptr;
}

void
rg_close( rg_reader* r )
{
    delete r;
}

const char*
rg_error( rg_reader* r )
{
    return r->error.c_str();
}

long long
rg_read( rg_reader* r,
         char*      buf,
         size_t     n )
{
    return guarded( r, [&] () { return static_cast<long long>( r->reader->read( buf, n ) ); } );
}

long long
rg_seek( rg_reader* r,
         long long  offset,
         int        whence )
{
    return guarded( r, [&] () { return static_cast<long long>( r->reader->seek( offset, whence ) ); } );
}

long long
rg_tell( rg_reader* r )
{
    return guarded( r, [&] () { return static_cast<long long>( r->reader->tell() ); } );
}

long long
rg_size( rg_reader* r )
{
    return guarded( r, [&] () {
        const auto size = r->reader->size();
        return size ? static_cast<long long>( *size ) : -1LL;
    } );
}

int
rg_export_index( rg_reader* r,
                 uintptr_t  writer )
{
    return static_cast<int>( guarded( r, [&] () {
        r->reader->exportIndex( [writer] ( const void* buffer, size_t size ) {
            if ( goWrite( writer, const_cast<void*>( buffer ), size ) != 0 ) {
                throw std::runtime_error( "writing the index failed" );
            }
        } );
        return 0LL;
    } ) );
}

int
rg_import_index( rg_reader* r,
                 uintptr_t  handle,
                 uint64_t   size )
{
    return static_cast<int>( guarded( r, [&] () {
        r->reader->importIndex( std::make_unique<GoFileReader>( handle, static_cast<size_t>( size ) ) );
        return 0LL;
    } ) );
}

}  // extern "C"
