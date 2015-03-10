#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <wait.h>

#include "ptrace.h"

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

	// make sure the target process received SIGTRAP after stopping.
	checktargetsig(target);
}

void ptrace_setregs(pid_t target, struct user_regs_struct* regs)
{
	if(ptrace(PTRACE_SETREGS, target, NULL, regs) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_SETREGS) failed\n");
		exit(1);
	}
}

siginfo_t ptrace_getsiginfo(pid_t target)
{
	siginfo_t targetsig;
	if(ptrace(PTRACE_GETSIGINFO, target, NULL, &targetsig) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_GETSIGINFO) failed\n");
		exit(1);
	}
	return targetsig;
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
		if(word == -1)
		{
			fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed\n");
			exit(1);
		}
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
		if(word == -1)
		{
			fprintf(stderr, "ptrace(PTRACE_POKETEXT) failed\n");
			exit(1);
		}
		byteCount += sizeof(word);
	}
}

void checktargetsig(int pid)
{
	// check the signal that the child stopped with.
	siginfo_t targetsig = ptrace_getsiginfo(pid);

	// if it wasn't SIGTRAP, then something bad happened (most likely a
	// segfault).
	if(targetsig.si_signo != SIGTRAP)
	{
		fprintf(stderr, "target stopped with signal %d instead of SIGTRAP\n", targetsig.si_signo);
		exit(1);
	}
}
