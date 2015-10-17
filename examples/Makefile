CC=gcc
CFLAGS=-lrt
EXE=alloc hello process shm

all: $(EXE)

alloc: alloc.c
	$(CC) -o $@ $< $(CFLAGS)

hello: hello.c
	$(CC) -o $@ $< $(CFLAGS)

process: process.c
	$(CC) -o $@ $< $(CFLAGS)

shm: shm.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -f $(EXE)
