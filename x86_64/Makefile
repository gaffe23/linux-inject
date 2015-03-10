CC	= clang

all: ../inject

../inject: inject.c
	$(CC) -std=gnu99 -ggdb -ldl -o ../inject ../utils.c inject.c
