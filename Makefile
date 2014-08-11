.PHONY: clean all
.SUFFIXES: .so .c

CC = gcc -Wall
LIBS = -lm -llua -lnpf

all: npf.so

.c.so:
	$(CC) -shared -o $(.TARGET) $(.ALLSRC) $(LIBS)

clean:
	rm -f *.o *.so *.core 
