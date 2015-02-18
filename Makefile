CC	= clang

arm: arm-inject target arm/library.c
	$(CC) -std=gnu99 -D_GNU_SOURCE -ggdb -c -fPIC arm/library.c -o library.o
	$(CC) -std=gnu99 -D_GNU_SOURCE -ggdb -shared -o library.so -fPIC arm/library.c

arm-inject: arm/inject.c
	$(CC) -std=gnu99 -ggdb -ldl -o inject arm/inject.c
	
x86_64: x86_64-inject target x86_64/library.c
	$(CC) -std=gnu99 -D_GNU_SOURCE -ggdb -c -fPIC x86_64/library.c -o library.o
	$(CC) -std=gnu99 -D_GNU_SOURCE -ggdb -shared -o library.so -fPIC x86_64/library.c

x86_64-inject: x86_64/inject.c
	$(CC) -std=gnu99 -ggdb -ldl -o inject x86_64/inject.c

target: target.c
	$(CC) -std=gnu99 -ggdb -ldl -o target target.c

clean:
	rm -f library.o
	rm -f library.so
	rm -f target
	rm -f inject
