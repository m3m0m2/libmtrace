// Copyright (C) 2023, Mauro Meneghin <m3m0m2 @ gmail.com>
//
// Trace all memory [/re/de]-allocations showing also a backtrace.
//
// Idea taken from: https://stackoverflow.com/questions/6083337/overriding-malloc-using-the-ld-preload-mechanism
//
// Intended to work with multithreaded apps, but untested.
// Requires GCC.
//
// Use:
//   LD_PRELOAD=./libmtrace.so /bin/pwd
//
// Output to stderr or set MTRACE_OUT to write to a file.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
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
static void* (*real_memalign)(size_t blocksize, size_t bytes) = NULL;

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
    log_message("# Thread: %d, nested: %d\n", thread_id, thread_use);

    if (fmt != NULL)
    {
        if (thread_use > 1)
        {
            for (int i=1; i<thread_use; i++)
                log_message("-");
            log_message(" ");
        }

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

    real_malloc   = dlsym(RTLD_NEXT, "malloc");
    real_free     = dlsym(RTLD_NEXT, "free");
    real_calloc   = dlsym(RTLD_NEXT, "calloc");
    real_realloc  = dlsym(RTLD_NEXT, "realloc");
    real_memalign = dlsym(RTLD_NEXT, "memalign");

    if (!real_malloc || !real_free || !real_calloc || !real_realloc || !real_memalign)
    {
        log_message("Error in `dlsym`: %s\n", dlerror());
        exit(1);
    }

    __atomic_store_n(&init_completed, 1, __ATOMIC_SEQ_CST);
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

void* calloc(size_t nmemb, size_t size)
{
    if (real_calloc == NULL)
        init();

    void* ptr = real_calloc(nmemb, size);

    print_backtrace("calloc(%lu, %lu)\n", nmemb, size);
    return ptr;
}

void* memalign(size_t blocksize, size_t bytes)
{
    if (real_memalign == NULL)
        init();
    void* ptr = real_memalign(blocksize, bytes);

    print_backtrace("memalign(%lu, %lu)\n", blocksize, bytes);
    return ptr;
}
