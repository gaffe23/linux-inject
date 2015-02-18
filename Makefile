CC	= clang

arm: arm-inject target library.o
x86_64: x86_64-inject target library.o

library.o: library.h library.c
	$(CC) -std=gnu99 -D_GNU_SOURCE -ggdb -c -fPIC library.c -o library.o
	$(CC) -std=gnu99 -D_GNU_SOURCE -ggdb -shared -o library.so -fPIC library.c

target: target.c
	$(CC) -std=gnu99 -ggdb -ldl -o target target.c

arm-inject: arm/inject.c
	$(CC) -std=gnu99 -ggdb -ldl -o inject arm/inject.c

x86_64-inject: x86_64/inject.c
	$(CC) -std=gnu99 -ggdb -ldl -o inject x86_64/inject.c

clean:
	rm -f library.so library.o
	rm -f target
	rm -f arm/inject
	rm -f x86_64/inject
