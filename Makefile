CC	= clang
CFLAGS	= -std=gnu99 -ggdb

all:
	$(error Please choose an architecture to build for: "make arm", "make x86", "make x86_64")

arm: sample-target sample-library.so
	$(CC) -marm $(CFLAGS) -DARM -o inject utils.c ptrace.c inject-arm.c -ldl

x86: sample-target sample-library.so
	$(CC) $(CFLAGS) -o inject utils.c ptrace.c inject-x86.c -ldl
	
x86_64:
	$(CC) $(CFLAGS) -o inject utils.c ptrace.c inject-x86_64.c -ldl
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o sample-library.so -fPIC sample-library.c
	$(CC) $(CFLAGS) -o sample-target sample-target.c
	$(CC) -m32 $(CFLAGS) -o inject32 utils.c ptrace.c inject-x86.c -ldl
	$(CC) -m32 $(CFLAGS) -D_GNU_SOURCE -shared -o sample-library32.so -fPIC sample-library.c
	$(CC) -m32 $(CFLAGS) -o sample-target32 sample-target.c

sample-library.so: sample-library.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o sample-library.so -fPIC sample-library.c

sample-target: sample-target.c
	$(CC) $(CFLAGS) -o sample-target sample-target.c

clean:
	rm -f sample-library.so
	rm -f sample-target
	rm -f inject
	rm -f sample-library32.so
	rm -f sample-target32
	rm -f inject32
