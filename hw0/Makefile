LIBINCLUDE = -ltrace -lm
LIBDIR = ../lib/massdal
CC = gcc
CFLAGS = -Wall -g
SRCDIR = ../src

yk_demo_hash: yk_demo_hash.c
	$(CC) $(CFLAG) -o yk_demo_hash yk_demo_hash.c $(LIBDIR)/prng.c $(LIBINCLUDE)
yk_sourcedemo: yk_sourcedemo.c
	gcc -o yk_sourcedemo yk_sourcedemo.c $(LIBINCLUDE)

clean:
	rm -f yk_demo_hash
	
