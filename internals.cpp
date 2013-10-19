#include "internals.h"
#include "tracing.h"

#include <cstring>

#include <unistd.h>
#include <sys/mman.h>

#include <algorithm>

namespace
{
    size_t const BLOCK_MAGIC = 0xdeadbeaf;

    struct block_header
    {
        void* start_address;
        size_t total_size;
        size_t data_size;
        size_t alignment;
        size_t magic;
    };

    size_t roundup(size_t n, size_t alignment)
    {
        return (n + alignment - 1) / alignment * alignment;
    }

    block_header* block_by_ptr(void* p)
    {
        void* ptr = (char*)p - sizeof(block_header);
        block_header* blk = (block_header*)ptr;

        if (blk->magic != BLOCK_MAGIC)
        {
            malloc_intercept::print("bad magic in block ", p, "\n");
            std::abort();
        }

        return blk;
    }

    bool is_power_of_2(size_t n)
    {
        return ((n != 0) && !(n & (n - 1))); 
    }
}

void* malloc_intercept::internal_alloc(size_t size, size_t alignment)
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
    blk->alignment     = alignment;
    blk->magic         = BLOCK_MAGIC;

    return (char*)ptr + data_start_offset;
}

void malloc_intercept::internal_free(void* ptr)
{
    if (ptr == NULL)
        return;

    block_header* blk = block_by_ptr(ptr);
    munmap(blk->start_address, blk->total_size);
}

void* malloc_intercept::internal_realloc(void *ptr, size_t size)
{
    if (ptr == NULL)
        return internal_alloc(size, DEFAULT_ALIGNMENT);

    // I don't know what size of alignment to use when realloc is called on block allocated with posix_memalign
    // Let's just preserve old alignment

    block_header* old_blk = block_by_ptr(ptr);

    void* new_data = internal_alloc(size, old_blk->alignment);
    if (new_data == NULL)
        return NULL;

    memcpy(new_data, ptr, std::min(size, old_blk->data_size));

    internal_free(ptr);

    return new_data;
}

bool malloc_intercept::is_valid_alignment(size_t alignment)
{
    if ((alignment % sizeof(void*)) != 0)
        return false;

    if (!is_power_of_2(alignment))
        return false;

    return true;
}
