CC	= clang

all:
	$(error Please choose an arch to build for: "make arm", "make x86_64")

arm: arm-inject target library.o

arm-inject: arm/inject.c
	$(CC) -std=gnu99 -ggdb -ldl -o inject arm/inject.c
	
x86_64: x86_64-inject target library.o

x86_64-inject: x86_64/inject.c
	$(CC) -std=gnu99 -ggdb -ldl -o inject x86_64/inject.c

library.o: library.c
	$(CC) -std=gnu99 -D_GNU_SOURCE -ggdb -c -fPIC library.c -o library.o
	$(CC) -std=gnu99 -D_GNU_SOURCE -ggdb -shared -o library.so -fPIC library.c

target: target.c
	$(CC) -std=gnu99 -ggdb -ldl -o target target.c

clean:
	rm -f library.o
	rm -f library.so
	rm -f target
	rm -f inject
