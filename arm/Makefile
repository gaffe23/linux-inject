CC	= clang

all: ../inject

../inject: inject.c ../utils.c
	$(CC) -std=gnu99 -ggdb -ldl -o ../inject ../utils.c inject.c
