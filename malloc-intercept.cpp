// compile (debug):   g++ --shared -fPIC -g -o malloc-intercept.so malloc-intercept.cpp
// compile (release): g++ --shared -fPIC -O2 -o malloc-intercept.so malloc-intercept.cpp
// run (trace):       LD_PRELOAD=./malloc-intercept.so kreversi
// run (no trace):    LD_PRELOAD=./malloc-intercept.so MALLOC_INTERCEPT_NO_TRACE=1 kreversi
// view symbols:      objdump -t --demangle malloc-intercept.so

#include <cstdio>
#include <cstring>
#include <cerrno>

#include <algorithm>

#include <unistd.h>
#include <sys/mman.h>


namespace
{
    size_t const BLOCK_MAGIC = 0xdeadbeaf;
    size_t const DEFAULT_ALIGNMENT = 8;

    struct block_header
    {
        void* start_address;
        size_t total_size;
        size_t data_size;
        size_t magic;
    };

    size_t roundup(size_t n, size_t alignment)
    {
        return (n + alignment - 1) / alignment * alignment;
    }

    void* internal_alloc(size_t size, size_t alignment)
    {
        size_t data_start_offset = roundup(sizeof(block_header), alignment);
        size_t header_start_offset = data_start_offset - sizeof(block_header);

        size_t total_size = data_start_offset + size;

        bool big_alignment = alignment > sysconf(_SC_PAGESIZE);
        if (big_alignment)
            total_size += alignment - 1;

        void* ptr = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == NULL)
            return NULL;

        if (big_alignment)
        {
            size_t ptrnum = (size_t)ptr;
            size_t alignment_size = roundup(ptrnum, alignment) - ptrnum;

            data_start_offset   += alignment_size;
            header_start_offset += alignment_size;
        }

        block_header* blk = (block_header*)((char*)ptr + header_start_offset);

        blk->start_address = ptr;
        blk->total_size    = total_size;
        blk->data_size     = size;
        blk->magic         = BLOCK_MAGIC;

        return (char*)ptr + data_start_offset;
    }

    block_header* block_by_ptr(void* p)
    {
        void* ptr = (char*)p - sizeof(block_header);
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
        munmap(blk->start_address, blk->total_size);
    }

    void* internal_realloc(void *ptr, size_t size)
    {
        if (ptr == NULL)
            return internal_alloc(size, DEFAULT_ALIGNMENT);

        // I don't know what size of alignment to use when realloc is called on block allocated with posix_memalign
        void* new_data = internal_alloc(size, DEFAULT_ALIGNMENT);
        if (new_data == NULL)
            return NULL;

        block_header* old_blk = block_by_ptr(ptr);

        memcpy(new_data, ptr, std::min(size, old_blk->data_size));

        internal_free(ptr);

        return new_data;
    }

    bool trace_enabled()
    {
        static bool enabled = (getenv("MALLOC_INTERCEPT_NO_TRACE") == NULL);
        return enabled;
    }

    bool is_power_of_2(size_t n)
    {
        return (n & (n >> 1)) == 0;
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

    if ((alignment % sizeof(void*)) != 0)
        return EINVAL;

    if (!is_power_of_2(alignment))
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
