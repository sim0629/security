CC=gcc
CFLAGS=

all: hello alloc

hello: hello.c
	$(CC) -o $@ $< $(CFLAGS)

alloc: alloc.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -f hello
