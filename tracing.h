#ifndef TRACING_H
#define TRACING_H

#include <cstdlib>
#include <limits>

// Generally its a bad idea to call I/O function from malloc
// if they call malloc we will end up with an infinite recursion.
// This file contains simple tracing functions which don't use malloc.
// You can use them instead of std::cerr or fprintf.
// This code is known to be incomplet and incorrekt and it lacks
// support of signed types.

namespace malloc_intercept
{
    void print_object(char const*);
    void print_object(void* px);
    void print_object(size_t n);
    
    void print();

    template <typename T, typename ... Ts>
    void print(T obj, Ts ... objs)
    {
        print_object(obj);
        print(objs...);
    }

    bool trace_enabled();

    template <typename ... Ts>
    void trace(Ts ... objs)
    {
        if (!trace_enabled())
            return;
        
        print(objs...);
    }
}

#endif
