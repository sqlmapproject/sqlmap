/* 
	lib_postgresqludf_sys - a library with miscellaneous (operating) system level functions
	Copyright (C) 2009-2010  Bernardo Damele A. G.
	web: http://bernardodamele.blogspot.com/
	email: bernardo.damele@gmail.com
	
	This library is free software; you can redistribute it and/or
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

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
#define _USE_32BIT_TIME_T
#define DLLEXP __declspec(dllexport) 
#define BUILDING_DLL 1
#else
#define DLLEXP
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <postgres.h>
#include <fmgr.h>
#include <stdlib.h>
#include <string.h>

#include <ctype.h>

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
DWORD WINAPI exec_payload(LPVOID lpParameter);
#endif

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

PG_FUNCTION_INFO_V1(sys_exec);
#ifdef PGDLLIMPORT
extern PGDLLIMPORT Datum sys_exec(PG_FUNCTION_ARGS) {
#else
extern DLLIMPORT Datum sys_exec(PG_FUNCTION_ARGS) {
#endif
	text *argv0 = PG_GETARG_TEXT_P(0);
	int32 argv0_size;
	int32 result = 0;
	char *command;

	argv0_size = VARSIZE(argv0) - VARHDRSZ;
	command = (char *)malloc(argv0_size + 1);

	memcpy(command, VARDATA(argv0), argv0_size);
	command[argv0_size] = '\0';

	/*
	Only if you want to log
	elog(NOTICE, "Command execution: %s", command);
	*/

	result = system(command);
	free(command);

	PG_FREE_IF_COPY(argv0, 0);
	PG_RETURN_INT32(result);
}

PG_FUNCTION_INFO_V1(sys_eval);
#ifdef PGDLLIMPORT
extern PGDLLIMPORT Datum sys_eval(PG_FUNCTION_ARGS) {
#else
extern DLLIMPORT Datum sys_eval(PG_FUNCTION_ARGS) {
#endif
	text *argv0 = PG_GETARG_TEXT_P(0);
	text *result_text;
	int32 argv0_size;
	char *command;
	char *result;
	FILE *pipe;
	char line[1024];
	int32 outlen, linelen;

	argv0_size = VARSIZE(argv0) - VARHDRSZ;
	command = (char *)malloc(argv0_size + 1);

	memcpy(command, VARDATA(argv0), argv0_size);
	command[argv0_size] = '\0';

	/*
	Only if you want to log
	elog(NOTICE, "Command evaluated: %s", command);
	*/

	result = (char *)malloc(1);
	outlen = 0;

	pipe = popen(command, "r");

	while (fgets(line, sizeof(line), pipe) != NULL) {
		linelen = strlen(line);
		result = (char *)realloc(result, outlen + linelen);
		strncpy(result + outlen, line, linelen);
		outlen = outlen + linelen;
	}

	pclose(pipe);

	if (*result) {
		result[outlen-1] = 0x00;
	}

	result_text = (text *)malloc(VARHDRSZ + strlen(result));
#ifdef SET_VARSIZE
	SET_VARSIZE(result_text, VARHDRSZ + strlen(result));
#else
	VARATT_SIZEP(result_text) = strlen(result) + VARHDRSZ;
#endif
	memcpy(VARDATA(result_text), result, strlen(result));

	PG_RETURN_POINTER(result_text);
}

PG_FUNCTION_INFO_V1(sys_bineval);
#ifdef PGDLLIMPORT
extern PGDLLIMPORT Datum sys_bineval(PG_FUNCTION_ARGS) {
#else
extern DLLIMPORT Datum sys_bineval(PG_FUNCTION_ARGS) {
#endif
	text *argv0 = PG_GETARG_TEXT_P(0);
	int32 argv0_size;
	size_t len;

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
	int pID;
	char *code;
#else
	int *addr;
	size_t page_size;
	pid_t pID;
#endif

	argv0_size = VARSIZE(argv0) - VARHDRSZ;
	len = (size_t)argv0_size;

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
	// allocate a +rwx memory page
	code = (char *) VirtualAlloc(NULL, len+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	strncpy(code, VARDATA(argv0), len);

	WaitForSingleObject(CreateThread(NULL, 0, exec_payload, code, 0, &pID), INFINITE);
#else
	pID = fork();
	if(pID<0)
		PG_RETURN_INT32(1);

	if(pID==0)
	{
		page_size = (size_t)sysconf(_SC_PAGESIZE)-1;	// get page size
		page_size = (len+page_size) & ~(page_size);		// align to page boundary

		// mmap an rwx memory page
		addr = mmap(0, page_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS, 0, 0);

		if (addr == MAP_FAILED)
			PG_RETURN_INT32(1);

		strncpy((char *)addr, VARDATA(argv0), len);

		((void (*)(void))addr)();
	}

	if(pID>0)
		waitpid(pID, 0, WNOHANG);
#endif

	PG_RETURN_INT32(0);
}

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
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

#undef fopen

PG_FUNCTION_INFO_V1(sys_fileread);
#ifdef PGDLLIMPORT
extern PGDLLIMPORT Datum sys_fileread(PG_FUNCTION_ARGS) {
#else
extern DLLIMPORT Datum sys_fileread(PG_FUNCTION_ARGS) {
#endif
	text *argv0 = PG_GETARG_TEXT_P(0);
	text *result_text;
	int32 argv0_size;
	int32 len;
	int32 i, j;
	char *filename;
	char *result;
	char *buffer;
	char table[] = "0123456789ABCDEF";
	FILE *file;

	argv0_size = VARSIZE(argv0) - VARHDRSZ;
	filename = (char *)malloc(argv0_size + 1);

	memcpy(filename, VARDATA(argv0), argv0_size);
	filename[argv0_size] = '\0';
	
	file = fopen(filename, "rb");
	if (!file)
	{
		PG_RETURN_NULL();
	}
	fseek(file, 0, SEEK_END);
	len = ftell(file);
	fseek(file, 0, SEEK_SET);

	buffer=(char *)malloc(len + 1);
	if (!buffer)
	{
		fclose(file);
		PG_RETURN_NULL();
	}

	fread(buffer, len, 1, file);
	fclose(file);

	result = (char *)malloc(2*len + 1);
	for (i=0, j=0; i<len; i++)
	{
		result[j++] = table[(buffer[i] >> 4) & 0x0f];
		result[j++] = table[ buffer[i]	   & 0x0f];
	}
	result[j] = '\0';
	
	result_text = (text *)malloc(VARHDRSZ + strlen(result));
#ifdef SET_VARSIZE
	SET_VARSIZE(result_text, VARHDRSZ + strlen(result));
#else
	VARATT_SIZEP(result_text) = strlen(result) + VARHDRSZ;
#endif
	memcpy(VARDATA(result_text), result, strlen(result));
	
	free(result);
	free(buffer);
	free(filename);

	PG_RETURN_POINTER(result_text);
}
