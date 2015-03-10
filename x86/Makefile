CC	= clang

all: ../inject

../inject: inject.c
	$(CC) -std=gnu99 -ggdb -ldl -o ../inject ../utils.c ../ptrace.c inject.c
