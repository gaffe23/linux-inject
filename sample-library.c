#include <stdio.h>
#include <dlfcn.h>

/*
 * hello()
 *
 * Hello world function exported by the sample library.
 *
 */

void hello()
{
	printf("Hello world!\n");
}

/*
 * loadMsg()
 *
 * This function is automatically called when the sample library is injected
 * into a process. It calls dladdr() on the hello() function above in order to
 * obtain a Dl_info structure containing information about the hello()
 * function. This Dl_info structure contains a member dli_fbase, which contains
 * the address where the library has been loaded.
 *
 */

__attribute__((constructor))
void loadMsg()
{
	Dl_info info;
	dladdr(hello, &info);
	printf("I just got loaded at 0x%08lx\n", (unsigned long)info.dli_fbase);
}
