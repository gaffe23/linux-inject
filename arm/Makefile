CC	= clang
CFLAGS	= -std=gnu99 -ggdb

all: ../inject

../inject: inject.c ../utils.c
	$(CC) -DARM -ldl -o ../inject ../utils.c ../ptrace.c inject.c
