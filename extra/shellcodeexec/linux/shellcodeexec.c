/*
	shellcodeexec - Script to execute in memory a sequence of opcodes
	Copyright (C) 2011  Bernardo Damele A. G.
	web: http://bernardodamele.blogspot.com
	email: bernardo.damele@gmail.com
	
	This source code is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.
	
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
	
	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
#include <windows.h>
DWORD WINAPI exec_payload(LPVOID lpParameter);
#else
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

int sys_bineval(char *argv);

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Run:\n\tshellcodeexec <alphanumeric-encoded shellcode>\n");
		exit(-1);
	}

	sys_bineval(argv[1]);

	exit(0);
}

int sys_bineval(char *argv)
{
	size_t len;

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
	int pID;
	char *code;
#else
	int *addr;
	size_t page_size;
	pid_t pID;
#endif

	len = (size_t)strlen(argv);

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
	// allocate a +rwx memory page
	code = (char *) VirtualAlloc(NULL, len+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// copy over the shellcode
	strncpy(code, argv, len);

	// execute it by ASM code defined in exec_payload function
	WaitForSingleObject(CreateThread(NULL, 0, exec_payload, code, 0, &pID), INFINITE);
#else
	pID = fork();
	if(pID<0)
		return 1;

	if(pID==0)
	{
		page_size = (size_t)sysconf(_SC_PAGESIZE)-1;	// get page size
		page_size = (len+page_size) & ~(page_size);	// align to page boundary

		// mmap an +rwx memory page
		addr = mmap(0, page_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANON, 0, 0);

		if (addr == MAP_FAILED)
			return 1;

		// copy over the shellcode
		strncpy((char *)addr, argv, len);

		// execute it
		((void (*)(void))addr)();
	}

	if(pID>0)
		waitpid(pID, 0, WNOHANG);
#endif

	return 0;
}

#if defined(_WIN64)
void __exec_payload(LPVOID);

DWORD WINAPI exec_payload(LPVOID lpParameter)
{
	__try
	{
		__exec_payload(lpParameter);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return 0;
}
#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
DWORD WINAPI exec_payload(LPVOID lpParameter)
{
	__try
	{
		__asm
		{
			mov eax, [lpParameter]
			call eax
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return 0;
}
#endif
