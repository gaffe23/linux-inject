all: inject target library.o

library.o: library.h library.c
	gcc -std=gnu99 -D_GNU_SOURCE -ggdb -c -fPIC library.c -o library.o
	gcc -std=gnu99 -D_GNU_SOURCE -ggdb -shared -o library.so -fPIC library.c

target: target.c
	clang -std=gnu99 -ggdb -ldl -o target target.c

inject: inject.c
	clang -std=gnu99 -ggdb -ldl -o inject inject.c

clean:
	rm -f library.so library.o
	rm -f target
	rm -f inject
