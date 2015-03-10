#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <signal.h>
#include <wait.h>
#include <dlfcn.h>
#include "../utils.c"

#define INTEL_RET_INSTRUCTION 0xc3
#define INTEL_INT3_INSTRUCTION 0xcc

void ptrace_attach(pid_t target)
{
	int waitpidstatus;

	if(ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_ATTACH) failed\n");
		exit(1);
	}

	if(waitpid(target, &waitpidstatus, WUNTRACED) != target)
	{
		fprintf(stderr, "waitpid(%d) failed\n", target);
		exit(1);
	}
}

void ptrace_detach(pid_t target)
{
	if(ptrace(PTRACE_DETACH, target, NULL, NULL) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_DETACH) failed\n");
		exit(1);
	}
}

void ptrace_getregs(pid_t target, struct user_regs_struct* regs)
{
	if(ptrace(PTRACE_GETREGS, target, NULL, regs) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_GETREGS) failed\n");
		exit(1);
	}
}

void ptrace_cont(pid_t target)
{
	if(ptrace(PTRACE_CONT, target, NULL, NULL) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_CONT) failed\n");
		exit(1);
	}
}

void ptrace_setregs(pid_t target, struct user_regs_struct* regs)
{
	if(ptrace(PTRACE_SETREGS, target, NULL, regs) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_SETREGS) failed\n");
		exit(1);
	}
}

// used http://www.ars-informatica.com/Root/Code/2010_04_18/LinuxPTrace.aspx as a reference for this
void ptrace_read(int pid, unsigned long addr, void *vptr, int len)
{
	int bytesRead = 0;
	int i = 0;
	long word = 0;
	long *ptr = (long *) vptr;

	while (bytesRead < len)
	{
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
		bytesRead += sizeof(word);
		ptr[i++] = word;
	}
}

// used http://www.ars-informatica.com/Root/Code/2010_04_18/LinuxPTrace.aspx as a reference for this
void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
	int byteCount = 0;
	long word = 0;

	while (byteCount < len)
	{
		memcpy(&word, vptr + byteCount, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + byteCount, word);
		byteCount += sizeof(word);
	}
}

// this is the code that will actually be injected into the target process.
// this code is responsible for loading the shared library into the target
// process' address space.  first, it calls malloc() to allocate a buffer to
// hold the filename of the library to be loaded, then calls
// __libc_dlopen_mode(), libc's implementation of dlopen(), to load the desired
// shared library. finally, it calls free() to free the buffer containing the
// library name, and then it breaks into the debugger with an "int $3"
// instruction.
void injectSharedLibrary(long mallocaddr, long freeaddr, long dlopenaddr)
{
	// here are the assumptions I'm making about what data will be located where
	// at the time the target executes this code:
	//
	//   ebx = address of malloc() in target process
	//   edi = address of __libc_dlopen_mode() in target process
	//   esi = address of free() in target process

	// for some reason it's adding 1 to esi, so subtract 1 from it
	asm("dec %esi");

	// call malloc() from within the target process
	asm(
		// allocate 32 bytes
		// TODO: intelligently choose the amount of memory to allocate
		// here instead of always allocating 32 bytes
		"push $0x20 \n"
		// call malloc
		"call *%ebx \n"
		// copy return value into ebx
		"mov %eax, %ebx \n"
		// break into debugger so we can get the return value
		"int $3"
	);

	// call __libc_dlopen_mode() to load the shared library
	asm(
		// flag = RTLD_LAZY
		"push $1 \n"
		// push malloc addr
		"push %ebx \n"
		// call dlopen
		"call *%edi \n"
		// break into debugger so we can check the return value
		"int $3"
	);

	// call free() on the previously malloc()ed buffer
	asm(
		// push the address we want to free (the address we malloc'd earler)
		"push %ebx \n"
		// call free
		"call *%esi"
	);
}

// this function's only purpose in life is to be contiguous to injectSharedLibrary(),
// so that we can use it to more precisely figure out how long injectSharedLibrary() is
void injectSharedLibrary_end()
{
}

// starting at an address somewhere after the end of a function, search for the
// "ret" instruction that ends it. this should be safe, because function
// addresses are word-aligned and padded with "nop"s, so we'll basically search
// through a bunch of "nop"s before finding our "ret". in other words, it's
// unlikely that we'll run into a 0xc3 byte that corresponds to anything other
// than an actual RET instruction.
unsigned char* findRet(void* endAddr)
{
	unsigned char* retInstAddr = endAddr;
	while(*retInstAddr != INTEL_RET_INSTRUCTION)
	{
		retInstAddr--;
	}
	return retInstAddr;
}

// find the address of the given function within our currently-loaded libc
long getFunctionAddress(char* funcName)
{
	void* self = dlopen("libc.so.6", RTLD_NOLOAD);
	void* funcAddr = dlsym(self, funcName);
	return (long)funcAddr;
}

// restore backed up data and regs and let the target go on its merry way
void restoreStateAndDetach(pid_t target, unsigned long addr, void* backup, int datasize, struct user_regs_struct oldregs)
{
	ptrace_write(target, addr, backup, datasize);
	ptrace_setregs(target, &oldregs);
	ptrace_detach(target);
}

int main(int argc, char** argv)
{
	if(argc < 3)
	{
		printf("usage: %s [process-name] [library-to-inject]\n", argv[0]);
		return 1;
	}

	char* processName = argv[1];
	char* libname = argv[2];

	int mypid = getpid();
	long mylibcaddr = getlibcaddr(mypid);

	// find the addresses of the syscalls that we'd like to use inside the
	// target, as loaded inside THIS process (i.e. NOT the target process)
	long mallocAddr = getFunctionAddress("malloc");
	long freeAddr = getFunctionAddress("free");
	long dlopenAddr = getFunctionAddress("__libc_dlopen_mode");

	// use the base address of libc to calculate offsets for the syscalls
	// we want to use
	long mallocOffset = mallocAddr - mylibcaddr;
	long freeOffset = freeAddr - mylibcaddr;
	long dlopenOffset = dlopenAddr - mylibcaddr;

	pid_t target = findProcessByName(processName);
	if(target == -1)
	{
		fprintf(stderr, "doesn't look like a process named \"%s\" is running right now\n", processName);
		return 1;
	}

	printf("found process \"%s\" with pid %d\n", processName, target);

	// get the target process' libc address and use it to find the
	// addresses of the syscalls we want to use inside the target process
	long targetLibcAddr = getlibcaddr(target);
	long targetMallocAddr = targetLibcAddr + mallocOffset;
	long targetFreeAddr = targetLibcAddr + freeOffset;
	long targetDlopenAddr = targetLibcAddr + dlopenOffset;

	struct user_regs_struct oldregs, regs;
	memset(&oldregs, 0, sizeof(struct user_regs_struct));
	memset(&regs, 0, sizeof(struct user_regs_struct));

	ptrace_attach(target);

	ptrace_getregs(target, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	// find a good address to copy code to
	long addr = freespaceaddr(target) + sizeof(long);

	// now that we have an address to copy code to, set the target's eip to it.
	regs.eip = addr;

	// pass arguments to my function injectSharedLibrary() by loading them
	// into the right registers. see comments in injectSharedLibrary() for
	// more details.
	regs.ebx = targetMallocAddr;
	regs.edi = targetDlopenAddr;
	regs.esi = targetFreeAddr;
	ptrace_setregs(target, &regs);

	// figure out the size of injectSharedLibrary() so we know how big of a buffer to allocate. 
	int injectSharedLibrary_size = (int)injectSharedLibrary_end - (int)injectSharedLibrary;

	// also figure out where the RET instruction at the end of
	// injectSharedLibrary() lies so that we can overwrite it with an INT 3
	// in order to break back into the target process. gcc and clang both
	// force function addresses to be word-aligned, which means that
	// functions are padded at the end after the RET instruction that ends
	// the function. as a result, even though in theory we've found the
	// length of the function, it is very likely padded with NOPs, so we
	// still need to do a bit of searching to find the RET.
	int injectSharedLibrary_ret = (int)findRet(injectSharedLibrary_end) - (int)injectSharedLibrary;

	// back up whatever data used to be at the address we want to modify.
	char* backup = malloc(injectSharedLibrary_size * sizeof(char));
	ptrace_read(target, addr, backup, injectSharedLibrary_size);

	// set up the buffer containing the code to inject into the target process.
	char* newcode = malloc(injectSharedLibrary_size * sizeof(char));
	memset(newcode, 0, injectSharedLibrary_size * sizeof(char));

	// copy the code of injectSharedLibrary() to a buffer.
	memcpy(newcode, injectSharedLibrary, injectSharedLibrary_size - 1);
	// overwrite the RET instruction with an INT 3.
	newcode[injectSharedLibrary_ret] = INTEL_INT3_INSTRUCTION;

	// copy injectSharedLibrary()'s code to the target address inside the
	// target process' address space.
	ptrace_write(target, addr, newcode, injectSharedLibrary_size);

	// now that the new code is in place, let the target run our injected code.
	ptrace_cont(target);

	// at this point, the target should have run malloc(). check its return
	// value to see if it succeeded, and bail out cleanly if it didn't.
	struct user_regs_struct malloc_regs;
	memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &malloc_regs);
	unsigned long targetBuf = malloc_regs.eax;
	if(targetBuf == 0)
	{
		printf("malloc() failed to allocate memory\n");
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	// if we get here, then malloc likely succeeded, so now we need to copy
	// the path to the shared library we want to inject into the buffer
	// that the target process just malloc'd. this is needed so that it can
	// be passed as an argument to dlopen later on.

	// read the current value of eax, which contains malloc's return value,
	// and copy the name of our shared library to that address inside the
	// target process.
	ptrace_write(target, targetBuf, libname, strlen(libname)*sizeof(char));

	// now call __libc_dlopen_mode() to attempt to load the shared library.
	ptrace_cont(target);

	// check out what the registers look like after calling dlopen. 
	struct user_regs_struct dlopen_regs;
	memset(&dlopen_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &dlopen_regs);
	unsigned long long libAddr = dlopen_regs.eax;

	// if eax is 0 here, then dlopen failed, and we should bail out cleanly.
	if(libAddr == 0)
	{
		printf("__libc_dlopen_mode() failed to load %s\n", libname);
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	// if eax is nonzero, then our library was successfully injected.
	printf("library \"%s\" successfully injected\n", libname);

	// as a courtesy, free the buffer that we allocated inside the target
	// process. we don't really care whether this succeeds, so don't
	// bother checking the return value.
	ptrace_cont(target);

	// at this point, if everything went according to plan, we've loaded
	// the shared library inside the target process, so we're done. restore
	// the old state and detach from the target.
	restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
	free(backup);
	free(newcode);

	return 0;
}
