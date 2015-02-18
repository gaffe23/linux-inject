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

// I used s0beit's code as a reference to write this in C
pid_t findProcessByName(char* processName)
{
	if(processName == NULL)
	{
		return -1;
	}

	struct dirent *procDirs;

	DIR *directory = opendir("/proc/");

	if (directory)
	{
		while ((procDirs = readdir(directory)) != NULL)
		{
			if (procDirs->d_type != DT_DIR)
				continue;

			pid_t pid = atoi(procDirs->d_name);

			int exePathLen = 10 + strlen(procDirs->d_name) + 1;
			char* exePath = malloc(exePathLen * sizeof(char));

			if(exePath == NULL)
			{
				continue;
			}

			sprintf(exePath, "/proc/%s/exe", procDirs->d_name);
			exePath[exePathLen-1] = '\0';

			char* exeBuf = malloc(PATH_MAX * sizeof(char));
			if(exeBuf == NULL)
			{
				free(exePath);
				continue;
			}
			ssize_t len = readlink(exePath, exeBuf, PATH_MAX - 1);

			if(len == -1)
			{
				free(exePath);
				free(exeBuf);
				continue;
			}

			exeBuf[len] = '\0';

			char* exeName = NULL;
			char* exeToken = strtok(exeBuf, "/");
			while(exeToken)
			{
				exeName = exeToken;
				exeToken = strtok(NULL, "/");
			}

			if(strcmp(exeName, processName) == 0)
			{
				free(exePath);
				free(exeBuf);
				closedir(directory);
				return pid;
			}

			free(exePath);
			free(exeBuf);
		}

		closedir(directory);
	}

	return -1;
}

// search the target process' /proc/pid/maps entry and find an executable region of
// memory that we can use to run code in.
// started from http://www.ars-informatica.com/Root/Code/2010_04_18/LinuxPTrace.aspx
long freespaceaddr(pid_t pid)
{
	FILE *fp;
	char filename[30];
	char line[85];
	long addr;
	char str[20];
	char perms[5];
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		exit(1);
	while(fgets(line, 85, fp) != NULL)
	{
		sscanf(line, "%lx-%*lx %s %*s %s %*d", &addr, perms, str);

		if(strstr(perms, "x") != NULL)
		{
			break;
		}
	}
	fclose(fp);
	return addr;
}

// get the base address of libc inside process with pid "pid" using /proc/pid/maps
// started from http://www.ars-informatica.com/Root/Code/2010_04_18/LinuxPTrace.aspx
long getlibcaddr(pid_t pid)
{
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;
	char perms[5];
	char* modulePath;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		exit(1);
	while(fgets(line, 85, fp) != NULL)
	{
		sscanf(line, "%lx-%*lx %*s %*s %*s %*d", &addr);
		if(strstr(line, "libc") != NULL)
		{
			break;
		}
	}
	fclose(fp);
	return addr;
}

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

void ptrace_getregs(pid_t target, struct user_regs* regs)
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

void ptrace_setregs(pid_t target, struct user_regs* regs)
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
	int word = 0;

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

	// r1 = address of raise()
	// r2 = address of malloc()
	// r3 = address of __libc_dlopen_mode()
	// r4 = address of free()
	//
	// unfortunately, each function call we make will wipe out these
	// register values, so in order to save the function addresses, we need
	// to save them on the stack.
	//
	// here's the sequence of calls we're going to make:
	//
	// * malloc() - allocate a buffer to store the path to the shared
	// library to load
	//
	// * raise() - raise a SIGTRAP signal to break into the target process
	// so that we can check the return value of malloc() in order to know
	// where to copy the shared library path to
	//
	// * __libc_dlopen_mode() - load the shared library
	//
	// * raise() - raise a SIGTRAP signal to break into the target process
	// to check the return value of __libc_dlopen_mode() in order to see
	// whether it succeeded
	//
	// * free() - free the buffer containing the path to the shared library
	//
	// * raise() - raise a SIGTRAP signal to break into the target process
	// so that we can restore the parts of memory that we overwrote
	//
	// we need to push the addresses of the functions we want to call in
	// the reverse of the order we want to call them in (except for the
	// first call):

	asm("push {r1}");	// raise()
	asm("push {r4}");	// free()
	asm("push {r1}");	// raise()
	asm("push {r3}");	// __libc_dlopen_mode()
	asm("push {r1}");	// raise()

	// call malloc() to allocate 32 bytes to store the path to the shared library to inject.

	// TODO: the amount of memory to allocate should really be determined
	// by the actual length of the path to the library; as-is, this is not
	// likely to work if the path is longer than 32 characters.

	asm(
		// specify 32 bytes
		"mov r0, #32 \n"
		// call malloc(), whose address is already in r2
		"blx r2 \n"
		// copy return value r0 into r4 so that it doesn't get wiped out later
		"mov r5, r0"
	);

	// call raise(SIGTRAP) to get back control of the target.
	asm(
		// pop off the stack to get the address of raise()
		"pop {r1} \n"
		// specify SIGTRAP
		"mov r0, #5 \n"
		// call raise()
		"blx r1"
	);

	// call __libc_dlopen_mode() to actually load the shared library.
	asm(
		// pop off the stack to get the address of __libc_dlopen_mode()
		"pop {r2} \n"
		// copy r5 (the malloc'd buffer) into r0 to make it the first argument to __libc_dlopen_mode()
		"mov r0, r5 \n"
		// set the second argument to RTLD_LAZY
		"mov r1, #1 \n"
		// call __libc_dlopen_mode()
		"blx r2 \n"
		// copy return value r0 into r4 so that it doesn't get wiped out later
		"mov r4, r0"
	);

	// call raise(SIGTRAP) to get back control of the target.
	asm(
		// pop off the stack to get the address of raise()
		"pop {r1} \n"
		// specify SIGTRAP
		"mov r0, #5 \n"
		// call raise()
		"blx r1"
	);

	// call free() in order to free the buffer containing the path to the shared library.
	asm(
		// pop off the stack to get the address of free()
		"pop {r2} \n"
		// copy r5 (the malloc'd buffer) into r0 to make it the first argument to free()
		"mov r0, r5 \n"
		// call __libc_dlopen_mode()
		"blx r2 \n"
		// copy return value r0 into r4 so that it doesn't get wiped out later
		"mov r4, r0"
	);

	// call raise(SIGTRAP) to get back control of the target.
	asm(
		// pop off the stack to get the address of raise()
		"pop {r1} \n"
		// specify SIGTRAP
		"mov r0, #5 \n"
		// call raise()
		"blx r1"
	);
}

// this function's only purpose in life is to be contiguous to injectSharedLibrary(),
// so that we can use it to more precisely figure out how long injectSharedLibrary() is
void injectSharedLibrary_end()
{
}

// find the address of the given function within our currently-loaded libc
long getFunctionAddress(char* funcName)
{
	void* self = dlopen("libc.so.6", RTLD_NOLOAD);
	void* funcAddr = dlsym(self, funcName);
	return (long)funcAddr;
}

// restore backed up data and regs and let the target go on its merry way
void restoreStateAndDetach(pid_t target, unsigned long addr, void* backup, int datasize, struct user_regs oldregs)
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
	long raiseAddr = getFunctionAddress("raise");

	// use the base address of libc to calculate offsets for the syscalls
	// we want to use
	long mallocOffset = mallocAddr - mylibcaddr;
	long freeOffset = freeAddr - mylibcaddr;
	long dlopenOffset = dlopenAddr - mylibcaddr;
	long raiseOffset = raiseAddr - mylibcaddr;

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
	long targetRaiseAddr = targetLibcAddr + raiseOffset;

	struct user_regs oldregs, regs;
	memset(&oldregs, 0, sizeof(struct user_regs));
	memset(&regs, 0, sizeof(struct user_regs));

	ptrace_attach(target);

	ptrace_getregs(target, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct user_regs));

	// find a good address to copy code to
	long addr = freespaceaddr(target) + sizeof(long);

	// now that we have an address to copy code to, set the target's
	// program counter to it.
	//
	// subtract 4 bytes from the actual address, because ARM's PC actually
	// refers to the next instruction rather than the current instruction.
	regs.uregs[15] = addr - 4;

	// pass arguments to my function injectSharedLibrary() by loading them
	// into the right registers. see comments in injectSharedLibrary() for
	// more details.
	regs.uregs[1] = targetRaiseAddr;
	regs.uregs[2] = targetMallocAddr;
	regs.uregs[3] = targetDlopenAddr;
	regs.uregs[4] = targetFreeAddr;

	ptrace_setregs(target, &regs);

	// figure out the size of injectSharedLibrary() so we know how big of a buffer to allocate. 
	int injectSharedLibrary_size = (int)injectSharedLibrary_end - (int)injectSharedLibrary;

	// back up whatever data used to be at the address we want to modify.
	char* backup = malloc(injectSharedLibrary_size * sizeof(char));
	ptrace_read(target, addr, backup, injectSharedLibrary_size);

	// set up a buffer containing the code that we'll inject into the target process.
	char* newcode = malloc(injectSharedLibrary_size * sizeof(char));
	memset(newcode, 0, injectSharedLibrary_size * sizeof(char));

	// copy the code of injectSharedLibrary() to the buffer.
	memcpy(newcode, injectSharedLibrary, injectSharedLibrary_size);

	// copy injectSharedLibrary()'s code to the target address inside the
	// target process' address space.
	ptrace_write(target, addr, newcode, injectSharedLibrary_size);

	// now that the new code is in place, let the target run our injected code.
	ptrace_cont(target);

	// at this point, the target should have run malloc(). check its return
	// value to see if it succeeded, and bail out cleanly if it didn't.
	struct user_regs malloc_regs;
	memset(&malloc_regs, 0, sizeof(struct user_regs));
	ptrace_getregs(target, &malloc_regs);
	unsigned long long targetBuf = malloc_regs.uregs[5];

	// if r5 is 0 here, then malloc failed, and we should bail out cleanly.
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

	// read the buffer returned by malloc() and copy the name of our shared
	// library to that address inside the target process.
	ptrace_write(target, targetBuf, libname, strlen(libname)*sizeof(char));

	// continue the target's execution again in order to call dlopen.
	ptrace_cont(target);

	// check out what the registers look like after calling dlopen. 
	struct user_regs dlopen_regs;
	memset(&dlopen_regs, 0, sizeof(struct user_regs));
	ptrace_getregs(target, &dlopen_regs);
	unsigned long long libAddr = dlopen_regs.uregs[4];

	// if r4 is 0 here, then dlopen failed, and we should bail out cleanly.
	if(libAddr == 0)
	{
		printf("__libc_dlopen_mode() failed to load %s\n", libname);
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	// if __libc_dlopen_mode() returned a nonzero value, then our library
	// was successfully injected.
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
