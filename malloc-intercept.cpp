// compile (debug):   g++ --shared -fPIC -g -o malloc-intercept.so malloc-intercept.cpp internals.cpp
// compile (release): g++ --shared -fPIC -O2 -o malloc-intercept.so malloc-intercept.cpp internals.cpp
// run (trace):       LD_PRELOAD=./malloc-intercept.so kreversi
// run (no trace):    LD_PRELOAD=./malloc-intercept.so MALLOC_INTERCEPT_NO_TRACE=1 kreversi
// view symbols:      objdump -T --demangle malloc-intercept.so

#include <cerrno>
#include <cstdio>

#include "internals.h"

using namespace malloc_intercept;

namespace
{
    bool trace_enabled()
    {
        static bool enabled = (getenv("MALLOC_INTERCEPT_NO_TRACE") == NULL);
        return enabled;
    }
}


extern "C"
void* malloc(size_t size)
{
    void *p = internal_alloc(size, DEFAULT_ALIGNMENT);

    if (trace_enabled())
        // its generally bad idea to call I/O function from malloc
        // if they call malloc we will end up with an infinite recursion...
        // this is why I use fprintf instead of std::cerr
        fprintf(stderr, "malloc %zu %p\n", size, p);

    return p;
}

extern "C"
void* calloc(size_t n, size_t size)
{
    void* p = internal_alloc(n * size, DEFAULT_ALIGNMENT);

    if (trace_enabled())
        fprintf(stderr, "calloc %zu %zu %p\n", n, size, p);

    return p;
}

extern "C"
void free(void *ptr)
{
    internal_free(ptr);

    if (trace_enabled())
        fprintf(stderr, "free %p\n", ptr);
}

extern "C"
void* realloc(void *ptr, size_t size)
{
    void* p = internal_realloc(ptr, size);

    if (trace_enabled())
        fprintf(stderr, "realloc %p %zu %p\n", ptr, size, p);

    return p;
}

extern "C"
int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    *memptr = 0;

    if (!is_valid_alignment(alignment))
        return EINVAL;

    void* p = internal_alloc(size, alignment);

    if (trace_enabled())
        fprintf(stderr, "posix_memalign %zu %zu %p\n", alignment, size, p);

    if (p == 0)
        return ENOMEM;

    *memptr = p;

    return 0;
}

extern "C"
void *valloc(size_t size)
{
    fprintf(stderr, "deprecated function valloc is not supported\n");
    std::abort();
}

extern "C"
void *memalign(size_t boundary, size_t size)
{
    fprintf(stderr, "deprecated function memalign is not supported\n");
    std::abort();
}
