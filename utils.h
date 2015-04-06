#define INTEL_RET_INSTRUCTION 0xc3
#define INTEL_INT3_INSTRUCTION 0xcc

pid_t findProcessByName(char* processName);
long freespaceaddr(pid_t pid);
long getlibcaddr(pid_t pid);
long getFunctionAddress(char* funcName);
unsigned char* findRet(void* endAddr);
void usage(char* name);
