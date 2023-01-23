// Copyright (C) 2023, Mauro Meneghin <m3m0m2 @ gmail.com>
//
// Trace all memory [/re/de]-allocations showing also a backtrace.
//

#include "config.h"

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Real callbacks
static void* (*real_calloc)(size_t nmemb, size_t size) = NULL;
static void* (*real_malloc)(size_t size) = NULL;
static void  (*real_free)(void* ptr) = NULL;
static void* (*real_realloc)(void* ptr, size_t size) = NULL;
static void* (*real_aligned_alloc)(size_t alignment, size_t bytes) = NULL;
static int (*real_posix_memalign)(void** ptr, size_t alignment, size_t bytes) = NULL;
static void* (*real_memalign)(size_t alignment, size_t bytes) = NULL;
// Ignoring obsolete methods: valloc, pvalloc, (memalign is also obsolete)
// aligned_alloc and posix_memalign are not deprecated

static int init_started = 0, init_completed = 0;

static int log_fd = 2;
static int log_lock = 0;

static __thread int thread_use = 0;     // to avoid infinite recursion
static __thread int thread_id = 0;

static void acquire_lock(int* lock)
{
    while (__atomic_exchange_n(lock, 1, __ATOMIC_SEQ_CST) != 0)
            ;
}

static void release_lock(int* lock)
{
    __atomic_exchange_n(lock, 0, __ATOMIC_SEQ_CST);
}

#define LOG_BUFFER_SIZE    500

// Declared static for optimization v.s. ideal local variable
// safe as the use of the buffer is atomic
static char log_buffer[LOG_BUFFER_SIZE];

static void log_message(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(log_buffer, LOG_BUFFER_SIZE, fmt, ap);
    va_end(ap);
    // Using write avoids *printf recursion
    write(log_fd, log_buffer, strlen(log_buffer));
}

static void log_message_v(const char *fmt, va_list* ap)
{
    vsnprintf(log_buffer, LOG_BUFFER_SIZE, fmt, *ap);
    // Using write avoids *printf recursion
    write(log_fd, log_buffer, strlen(log_buffer));
}

static void display_mallinfo()
{
    struct mallinfo mi;

    mi = mallinfo();

    log_message(" MALLINFO STATS\n");
    log_message(" ==============\n");
    log_message(" Total non-mmapped bytes (arena):       %d\n", mi.arena);
    log_message(" Num of free chunks (ordblks):          %d\n", mi.ordblks);
    log_message(" Num of free fastbin blocks (smblks):   %d\n", mi.smblks);
    log_message(" Num of mapped regions (hblks):         %d\n", mi.hblks);
    log_message(" Bytes in mapped regions (hblkhd):      %d\n", mi.hblkhd);
    log_message(" Max. total allocated space (usmblks):  %d\n", mi.usmblks);
    log_message(" Free bytes held in fastbins (fsmblks): %d\n", mi.fsmblks);
    log_message(" Total allocated space (uordblks):      %d\n", mi.uordblks);
    log_message(" Total free space (fordblks):           %d\n", mi.fordblks);
    log_message(" Topmost releasable block (keepcost):   %d\n", mi.keepcost);
}

static void print_backtrace(const char* fmt, ...)
{
    thread_use++;

    if (thread_id == 0)
        __atomic_store_n(&thread_id, gettid(), __ATOMIC_SEQ_CST);

    // Only acquire lock on the top level to avoid a deadlock
    int needs_lock = (thread_use == 1);
    if (needs_lock)
        acquire_lock(&log_lock);

    // For nested levels show indentation
    if (thread_use > 1)
    {
        for (int i=1; i<thread_use; i++)
            log_message("-");
        log_message(" ");
    }
    log_message("* %d ", thread_id);

    if (fmt != NULL)
    {
        va_list ap;
        va_start(ap, fmt);
        log_message_v(fmt, &ap);
        va_end(ap);
    }

    // Only print backtrace for the top level, avoid infinite recursion
    if (thread_use == 1)
    {
        void* callstack[128];

        // Backtrace with start/end markers
        log_message("[\n");
        int frames = backtrace(callstack, 128);
        backtrace_symbols_fd(callstack, frames, log_fd);
        log_message("]\n\n");
    }
    else
    {
        // Warn:
        // - cannot acquire lock, but it's already acquired by parent level
        // - cannot use printf because it uses malloc recursively
        log_message("\n");
    }

    if (needs_lock)
        release_lock(&log_lock);

    thread_use--;
}

static void init()
{
    // Only run once
    if (__atomic_exchange_n(&init_started, 1, __ATOMIC_SEQ_CST) != 0)
    {
        // Wait until init thread has completed
        while (__atomic_load_n(&init_completed, __ATOMIC_SEQ_CST) == 0)
            ;
        return;
    }

    const char* log_file = getenv("MTRACE_OUT");
    if (log_file != NULL)
    {
        log_fd = open(log_file, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        if (log_fd < 0)
        {
            log_fd = 2;
            log_message("Failed to open %s: %s\n", log_file, strerror(errno));
            exit(1);
        }
    }

    thread_use++;

    real_malloc   = dlsym(RTLD_NEXT, "malloc");
    real_calloc   = dlsym(RTLD_NEXT, "calloc");
    real_realloc  = dlsym(RTLD_NEXT, "realloc");
    real_free     = dlsym(RTLD_NEXT, "free");

#if ENABLE_ALIGNED_ALLOC
    real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
    assert(real_aligned_alloc);
#endif

#if ENABLE_POSIX_MEMALIGN
    real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
    assert(real_posix_memalign);
#endif

#if ENABLE_MEMALIGN
    real_memalign = dlsym(RTLD_NEXT, "memalign");
    assert(real_memalign);
#endif

    if (!real_malloc || !real_free || !real_calloc || !real_realloc)
    {
        log_message("Error in `dlsym`: %s\n", dlerror());
        exit(1);
    }

    __atomic_store_n(&init_completed, 1, __ATOMIC_SEQ_CST);

    if (atexit(display_mallinfo) != 0)
    {
        log_message("Error failed call to atexit()\n");
        exit(1);
    }

    thread_use--;
}

void* malloc(size_t size)
{
    if (real_malloc == NULL)
        init();

    void* ptr = real_malloc(size);

    print_backtrace("malloc(%lu) = %p\n", size, ptr);
    return ptr;
}

void free(void* ptr)
{
    if (real_free == NULL)
        init();
    real_free(ptr);

    print_backtrace("free(%p)\n", ptr);
}

void* realloc(void* ptr, size_t size)
{
    if (real_realloc == NULL)
        init();

    void* new_ptr = real_realloc(ptr, size);

    print_backtrace("realloc(%p, %lu) = %p\n", ptr, size, new_ptr);
    return new_ptr;
}

// Workaround: loading a c++ app dsym during init() seems to require 1 calloc
#define BOOTSTRAP_BUFFER_SIZE  1000
static char bootstrap_buffer[BOOTSTRAP_BUFFER_SIZE];
static int bootstrap_buffer_idx = 0;

static void* bootstrap_calloc(size_t size)
{
    if (bootstrap_buffer_idx + size >= BOOTSTRAP_BUFFER_SIZE)
    {
        log_message("## Error: Failed to allocate %lu bytes\n", size);
        exit(1);
    }
    void* ptr = bootstrap_buffer + bootstrap_buffer_idx;
    bootstrap_buffer_idx += size;
    return ptr;
}

void* calloc(size_t nmemb, size_t size)
{
    if (real_calloc == NULL)
    {
        if (thread_use > 0)
        {
            log_message("## Warning boostrap call calloc(%lu, %lu)\n", nmemb, size);
            return bootstrap_calloc(nmemb*size);
        }
        init();
    }

    void* ptr = real_calloc(nmemb, size);

    print_backtrace("calloc(%lu, %lu) = %p\n", nmemb, size, ptr);
    return ptr;
}

#if ENABLE_ALIGNED_ALLOC
void* aligned_alloc(size_t alignment, size_t bytes)
{
    if (real_aligned_alloc == NULL)
        init();
    void* ptr = real_aligned_alloc(alignment, bytes);

    print_backtrace("aligned_alloc(%lu, %lu) = %p\n", alignment, bytes, ptr);
    return ptr;
}
#endif

#if ENABLE_POSIX_MEMALIGN
int posix_memalign(void** ptr, size_t alignment, size_t bytes)
{
    if (real_aligned_alloc == NULL)
        init();
    int ret = real_posix_memalign(ptr, alignment, bytes);

    if (ret != 0)
        *ptr = NULL;
    // Printing = ptr is easier to handle
    print_backtrace("posix_memalign(%lu, %lu) = %p\n", alignment, bytes, *ptr);
    return ret;
}
#endif

#if ENABLE_MEMALIGN
void* memalign(size_t blocksize, size_t bytes)
{
    if (real_memalign == NULL)
        init();
    void* ptr = real_memalign(blocksize, bytes);

    print_backtrace("memalign(%lu, %lu) = %p\n", blocksize, bytes, ptr);
    return ptr;
}
#endif
