#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ptrace.h>

void sleepfunc()
{
	struct timespec* sleeptime = malloc(sizeof(struct timespec));

	sleeptime->tv_sec = 1;
	sleeptime->tv_nsec = 0;

	while(1)
	{
		printf("sleeping...\n");
		//
		printf("mallocing memory at 0x%p\n", malloc(32));
		//
		nanosleep(sleeptime, NULL);
	}

	free(sleeptime);
}

int main()
{
	sleepfunc();
	return 0;
}
