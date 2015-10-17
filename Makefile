CC=gcc
CFLAGS=

sandbox: sandbox.c sgm_syscallent.h
	$(CC) -o $@ $< $(CFLAGS)

example:
	cd examples; make; cd ..

clean:
	rm -f *.o sandbox
