# Libmtrace

## Summary

Libmtrace is an experimantal project to trace all memory allocation, reallocations and deallocations of a linux applications that uses libc.
A backtrace is provided for every memory allocation (exception for initial bootstrap).
Most calls at the very beginning and end are typically underlying libc allocation and can be ignored.
Thread ID is also shown.

## Author

- [Mauro Meneghin](https://github.com/m3m0m2/libmtrace)

## Build

Requires GCC:

```bash
  make
```

## Usage

To see expressive backtrace symbols the application to be inspected should be compiled using -rdynamic, for example:

```bash
  g++ test.cpp -o test -lpthread -rdynamic
```

This can then inspected as:

```bash
MTRACE_OUT=/dev/stdout LD_PRELOAD=./libmtrace.so ./test

LD_PRELOAD=./libmtrace.so /bin/pwd
```

If MTRACE_OUT is not specified the trace output will go to stderr.

## Notes

Very little testing currently done.

Initial idea taken from: https://stackoverflow.com/questions/6083337/overriding-malloc-using-the-ld-preload-mechanism

## License

[MIT](https://choosealicense.com/licenses/mit/)
