CC	= clang
CFLAGS	= -std=gnu99 -ggdb

all:
	$(error Please choose an arch to build for: "make arm", "make x86", "make x86_64")

arm: sample-target sample-library.o
	$(CC) $(CFLAGS) -DARM -ldl -o inject utils.c ptrace.c inject-arm.c

x86: sample-target sample-library.o
	$(CC) $(CFLAGS) -ldl -o inject utils.c ptrace.c inject-x86.c
	
x86_64: sample-target sample-library.o
	$(CC) $(CFLAGS) -ldl -o inject utils.c ptrace.c inject-x86_64.c

sample-library.o: sample-library.c
	$(CC) -std=gnu99 -D_GNU_SOURCE -ggdb -c -fPIC sample-library.c -o sample-library.o
	$(CC) -std=gnu99 -D_GNU_SOURCE -ggdb -shared -o sample-library.so -fPIC sample-library.c

sample-target: sample-target.c
	$(CC) -std=gnu99 -ggdb -ldl -o sample-target sample-target.c

clean:
	rm -f sample-library.o
	rm -f sample-library.so
	rm -f sample-target
	rm -f inject
