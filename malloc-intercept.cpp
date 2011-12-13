
// compile:      g++ -nostartfiles --shared -fPIC -g -ldl -o malloc-intercept.so malloc-intercept.cpp
// run:          LD_PRELOAD=./malloc-intercept.so kreversi
// view symbols: objdump -t --demangle malloc-intercept.so

#include <cstdio>
#include <cstdlib>
#include <cstring>

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

        if (!ptr)
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
            fprintf(stderr, "bad magic!\n");
            _exit(1);
        }

        return blk;
    }

    void internal_free(void* ptr)
    {
        block_header* blk = block_by_ptr(ptr);
        munmap(blk, blk->size + DATA_OFFSET);
    }
}

extern "C"
void* malloc(size_t size)
{
    void *p = internal_alloc(size);

    fprintf(stderr, "malloc %zu %p\n", size, p);

    return p;
}

extern "C"
void* calloc(size_t nmemb, size_t size)
{
    void* p = internal_alloc(nmemb * size);

    fprintf(stderr, "calloc %zu %zu %p\n", nmemb, size, p);

    return p;
}

extern "C"
void free(void *ptr)
{
    fprintf(stderr, "free %p\n", ptr);

    if (ptr == NULL)
        return;

    internal_free(ptr);
}

extern "C"
void* realloc(void *ptr, size_t size)
{
    if (ptr == NULL)
        return malloc(size);
    
    void* new_data = internal_alloc(size);
    if (new_data == NULL)
        return NULL;

    fprintf(stderr, "realloc %p %zu %p\n", ptr, size, new_data);

    block_header* old_blk = block_by_ptr(ptr);

    size_t size_to_copy = size < old_blk->size ? size : old_blk->size;
    memcpy(new_data, ptr, size_to_copy);

    internal_free(ptr);

    return new_data;
}
