#ifndef INTERNALS_H
#define INTERNALS_H

#include <cstdlib>

namespace malloc_intercept
{
    size_t const DEFAULT_ALIGNMENT = 8;

    void* internal_alloc    (size_t size, size_t alignment);
    void  internal_free     (void* ptr);
    void* internal_realloc  (void *ptr, size_t size);

    bool  is_valid_alignment(size_t alignment);
}

#endif
