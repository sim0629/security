CC=gcc
CFLAGS=-lrt
EXE=alloc file hello process shm

all: $(EXE)

alloc: alloc.c
	$(CC) -o $@ $< $(CFLAGS)

file: file.c
	$(CC) -o $@ $< $(CFLAGS)

hello: hello.c
	$(CC) -o $@ $< $(CFLAGS)

process: process.c
	$(CC) -o $@ $< $(CFLAGS)

shm: shm.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -f $(EXE)
