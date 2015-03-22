CC	= clang
CFLAGS	= -std=gnu99 -ggdb

all:
	$(error Please choose an architecture to build for: "make arm", "make x86", "make x86_64")

arm: sample-target sample-library.so
	$(CC) $(CFLAGS) -DARM -ldl -o inject utils.c ptrace.c inject-arm.c

x86: sample-target sample-library.so
	$(CC) $(CFLAGS) -ldl -o inject utils.c ptrace.c inject-x86.c
	
x86_64: sample-target sample-library.so
	$(CC) $(CFLAGS) -ldl -o inject utils.c ptrace.c inject-x86_64.c

sample-library.so: sample-library.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o sample-library.so -fPIC sample-library.c

sample-target: sample-target.c
	$(CC) $(CFLAGS) -o sample-target sample-target.c

clean:
	rm -f sample-library.so
	rm -f sample-target
	rm -f inject
