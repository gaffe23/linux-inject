CC	= clang

all:
	$(error Please choose an arch to build for: "make arm", "make x86", "make x86_64")

arm: target library.o
	make -C arm/

x86: target library.o
	make -C x86/
	
x86_64: target library.o
	make -C x86_64/

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
