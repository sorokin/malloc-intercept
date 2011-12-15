// compile (debug):   g++ --shared -fPIC -g -o malloc-intercept.so malloc-intercept.cpp
// compile (release): g++ --shared -fPIC -O2 -o malloc-intercept.so malloc-intercept.cpp
// run (trace):       LD_PRELOAD=./malloc-intercept.so kreversi
// run (no trace):    LD_PRELOAD=./malloc-intercept.so MALLOC_INTERCEPT_NO_TRACE=1 kreversi
// view symbols:      objdump -t --demangle malloc-intercept.so

#include <cstdio>
#include <cstring>

#include <algorithm>

#include <unistd.h>
#include <sys/mman.h>


namespace
{
    size_t const BLOCK_MAGIC = 0xdeadbeaf;
    size_t const DATA_OFFSET = 16;

    struct block_header
    {
        size_t size;
        size_t magic;
    };

    size_t roundup(size_t n, size_t alignment)
    {
        return (n + alignment - 1) / alignment * alignment;
        
    }

    void* internal_alloc(size_t size)
    {
        void* ptr = mmap(NULL, size + DATA_OFFSET, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (ptr == NULL)
            return NULL;

        block_header* blk = (block_header*)ptr;
        blk->size = size;
        blk->magic = BLOCK_MAGIC;

        return (char*)ptr + DATA_OFFSET;
    }

    block_header* block_by_ptr(void* p)
    {
        void* ptr = (char*)p - DATA_OFFSET;
        block_header* blk = (block_header*)ptr;

        if (blk->magic != BLOCK_MAGIC)
        {
            fprintf(stderr, "bad magic in block %p\n", p);
            std::abort();
        }

        return blk;
    }

    void internal_free(void* ptr)
    {
        if (ptr == NULL)
            return;

        block_header* blk = block_by_ptr(ptr);
        munmap(blk, blk->size + DATA_OFFSET);
    }

    void* internal_realloc(void *ptr, size_t size)
    {
        if (ptr == NULL)
            return internal_alloc(size);

        void* new_data = internal_alloc(size);
        if (new_data == NULL)
            return NULL;

        block_header* old_blk = block_by_ptr(ptr);

        memcpy(new_data, ptr, std::min(size, old_blk->size));

        internal_free(ptr);

        return new_data;
    }

    bool trace_enabled()
    {
        static bool enabled = (getenv("MALLOC_INTERCEPT_NO_TRACE") == NULL);
        return enabled;
    }
}


extern "C"
void* malloc(size_t size)
{
    void *p = internal_alloc(size);

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
    void* p = internal_alloc(n * size);

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
