#
# Copyright (C) 2023, Mauro Meneghin <m3m0m2 @ gmail.com>
#

CC ?= gcc
RM ?= rm

LIB=libmtrace.so
SOURCES=libmtrace.c

.PHONY: all clean

all: $(LIB)

$(LIB): $(SOURCES)
	$(CC) -shared -fPIC -o $@ $^ -ldl

clean:
	$(RM) -f -- $(LIB)
