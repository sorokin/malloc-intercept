// compile (debug):   g++ --shared -std=c++11 -fPIC -g -o malloc-intercept.so malloc-intercept.cpp internals.cpp tracing.cpp
// compile (release): g++ --shared -std=c++11 -fPIC -O2 -o malloc-intercept.so malloc-intercept.cpp internals.cpp tracing.cpp
// run (trace):       LD_PRELOAD=./malloc-intercept.so kreversi
// run (no trace):    LD_PRELOAD=./malloc-intercept.so MALLOC_INTERCEPT_NO_TRACE=1 kreversi
// view symbols:      objdump -T --demangle malloc-intercept.so

#include <cerrno>

#include "internals.h"
#include "tracing.h"

using namespace malloc_intercept;

namespace
{
    __thread bool inside_malloc = false;

    struct recuirsion_guard
    {
        recuirsion_guard()
        {
            if (inside_malloc)
            {
                print("recursive call\n");
                std::abort();
            }
            
            inside_malloc = true;
        }

        ~recuirsion_guard()
        {
            inside_malloc = false;
        }

    private:
        recuirsion_guard(recuirsion_guard const&);
        recuirsion_guard& operator=(recuirsion_guard const&);
    };
}


extern "C"
void* malloc(size_t size)
{
    recuirsion_guard rg;
    
    void *p = internal_alloc(size, DEFAULT_ALIGNMENT);
    trace("malloc ", size, " ", p, "\n");

    return p;
}

extern "C"
void* calloc(size_t n, size_t size)
{
    recuirsion_guard rg;

    void* p = internal_alloc(n * size, DEFAULT_ALIGNMENT);
    trace("calloc ", n, " ", size, " ", p, "\n");

    return p;
}

extern "C"
void free(void *ptr)
{
    recuirsion_guard rg;

    internal_free(ptr);
    trace("free ", ptr, "\n");
}

extern "C"
void* realloc(void *ptr, size_t size)
{
    recuirsion_guard rg;

    void* p = internal_realloc(ptr, size);
    trace("realloc ", ptr, " ", size, " ", p, "\n");

    return p;
}

extern "C"
int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    recuirsion_guard rg;

    *memptr = 0;

    if (!is_valid_alignment(alignment))
        return EINVAL;

    void* p = internal_alloc(size, alignment);

    trace("posix_memalign ", alignment, " ", size, " ", p, "\n");

    if (p == 0)
        return ENOMEM;

    *memptr = p;

    return 0;
}

extern "C"
void *valloc(size_t size)
{
    recuirsion_guard rg;

    print("deprecated function valloc is not supported\n");
    std::abort();
}

extern "C"
void *memalign(size_t boundary, size_t size)
{
    recuirsion_guard rg;

    print("deprecated function memalign is not supported\n");
    std::abort();
}
