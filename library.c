#include <stdio.h>
#include "library.h"
#include <dlfcn.h>

void hello()
{
	printf("Hello world!\n");
}

__attribute__((constructor))
void loadMsg()
{
	Dl_info  info;
	dladdr(hello, &info);
	printf("I just got loaded at 0x%016llx\n", (unsigned long long)info.dli_fbase);
}
