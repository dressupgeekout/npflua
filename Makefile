.PHONY: clean all
.SUFFIXES: .so .c

CC ?= gcc
CFLAGS = -fPIC -Weverything -Wno-padded -Wno-unused-parameter -Werror
LIBS = -lm -llua -lnpf

all: npf.so

.c.so:
	$(CC) $(CFLAGS) -shared -o $(.TARGET) $(.ALLSRC) $(LIBS)

clean:
	rm -f *.o *.so *.core
