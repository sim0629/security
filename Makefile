CC=gcc
CFLAGS=
OBJ=sandbox.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

sandbox: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

example:
	cd examples; make; cd ..

clean:
	rm -f *.o sandbox
