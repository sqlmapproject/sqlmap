/* 
	lib_mysqludf_sys - a library with miscellaneous (operating) system level functions
	Copyright (C) 2007  Roland Bouman 
	Copyright (C) 2008-2010  Roland Bouman and Bernardo Damele A. G.
	web: http://www.mysqludf.org/
	email: mysqludfs@gmail.com, bernardo.damele@gmail.com
	
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
#define DLLEXP __declspec(dllexport) 
#else
#define DLLEXP
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifdef STANDARD
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifdef __WIN__
typedef unsigned __int64 ulonglong;
typedef __int64 longlong;
#else
typedef unsigned long long ulonglong;
typedef long long longlong;
#endif /*__WIN__*/
#else
#include <my_global.h>
#include <my_sys.h>
#endif
#include <mysql.h>
#include <m_ctype.h>
#include <m_string.h>
#include <stdlib.h>

#include <ctype.h>

#ifdef HAVE_DLOPEN
#ifdef	__cplusplus
extern "C" {
#endif

#define LIBVERSION "lib_mysqludf_sys version 0.0.4"

#ifdef __WIN__
#define SETENV(name,value)		SetEnvironmentVariable(name,value);
#else
#define SETENV(name,value)		setenv(name,value,1);		
#endif

DLLEXP 
my_bool lib_mysqludf_sys_info_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
);

DLLEXP 
void lib_mysqludf_sys_info_deinit(
	UDF_INIT *initid
);

DLLEXP 
char* lib_mysqludf_sys_info(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char* result
,	unsigned long* length
,	char *is_null
,	char *error
);

/**
 * sys_get
 * 
 * Gets the value of the specified environment variable.
 */
DLLEXP 
my_bool sys_get_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
);

DLLEXP 
void sys_get_deinit(
	UDF_INIT *initid
);

DLLEXP 
char* sys_get(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char* result
,	unsigned long* length
,	char *is_null
,	char *error
);

/**
 * sys_set
 * 
 * Sets the value of the environment variables.
 * This function accepts a set of name/value pairs
 * which are then set as environment variables.
 * Use sys_get to retrieve the value of such a variable 
 */
DLLEXP 
my_bool sys_set_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
);

DLLEXP 
void sys_set_deinit(
	UDF_INIT *initid
);

DLLEXP 
long long sys_set(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *is_null
,	char *error
);

/**
 * sys_exec
 * 
 * executes the argument commandstring and returns its exit status.
 * Beware that this can be a security hazard.
 */
DLLEXP 
my_bool sys_exec_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
);

DLLEXP 
void sys_exec_deinit(
	UDF_INIT *initid
);

DLLEXP 
my_ulonglong sys_exec(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *is_null
,	char *error
);

/**
 * sys_eval
 * 
 * executes the argument commandstring and returns its standard output.
 * Beware that this can be a security hazard.
 */
DLLEXP 
my_bool sys_eval_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
);

DLLEXP 
void sys_eval_deinit(
	UDF_INIT *initid
);

DLLEXP 
char* sys_eval(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char* result
,	unsigned long* length
,	char *is_null
,	char *error
);

/**
 * sys_bineval
 * 
 * executes bynary opcodes.
 * Beware that this can be a security hazard.
 */
DLLEXP 
my_bool sys_bineval_init(
	UDF_INIT *initid
,	UDF_ARGS *args
);

DLLEXP 
void sys_bineval_deinit(
	UDF_INIT *initid
);

DLLEXP 
int sys_bineval(
	UDF_INIT *initid
,	UDF_ARGS *args
);

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
DWORD WINAPI exec_payload(LPVOID lpParameter);
#endif


#ifdef	__cplusplus
}
#endif

/**
 * lib_mysqludf_sys_info
 */
my_bool lib_mysqludf_sys_info_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
){
	my_bool status;
	if(args->arg_count!=0){
		strcpy(
			message
		,	"No arguments allowed (udf: lib_mysqludf_sys_info)"
		);
		status = 1;
	} else {
		status = 0;
	}
	return status;
}

void lib_mysqludf_sys_info_deinit(
	UDF_INIT *initid
){
}

char* lib_mysqludf_sys_info(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char* result
,	unsigned long* length
,	char *is_null
,	char *error
){
	strcpy(result,LIBVERSION);
	*length = strlen(LIBVERSION);
	return result;
}

my_bool sys_get_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
){
	if(args->arg_count==1
	&&	args->arg_type[0]==STRING_RESULT){
		initid->maybe_null = 1;
		return 0;
	} else {
		strcpy(
			message
		,	"Expected exactly one string type parameter"
		);		
		return 1;
	}
}

void sys_get_deinit(
	UDF_INIT *initid
){
}

char* sys_get(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char* result
,	unsigned long* length
,	char *is_null
,	char *error
){
	char* value = getenv(args->args[0]);
	if(value == NULL){
		*is_null = 1;
	} else {
		*length = strlen(value);
	} 
	return value;
}

my_bool sys_set_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
){
	if(args->arg_count!=2){
		strcpy(
			message
		,	"Expected exactly two arguments"
		);		
		return 1;
	}
	if(args->arg_type[0]!=STRING_RESULT){
		strcpy(
			message
		,	"Expected string type for name parameter"
		);		
		return 1;
	}
	args->arg_type[1]=STRING_RESULT;
	if((initid->ptr=malloc(
		args->lengths[0]
	+	1
	+	args->lengths[1]
	+	1
	))==NULL){
		strcpy(
			message
		,	"Could not allocate memory"
		);		
		return 1;
	}	
	return 0;
}

void sys_set_deinit(
	UDF_INIT *initid
){
	if (initid->ptr!=NULL){
		free(initid->ptr);
	}
}

long long sys_set(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *is_null
,	char *error
){	
	char *name = initid->ptr;
	char *value = name + args->lengths[0] + 1; 
	memcpy(
		name
	,	args->args[0]
	,	args->lengths[0]
	);
	*(name + args->lengths[0]) = '\0';
	memcpy(
		value
	,	args->args[1]
	,	args->lengths[1]
	);
	*(value + args->lengths[1]) = '\0';
	return SETENV(name,value);		
}

my_bool sys_exec_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
){
	unsigned int i=0;
	if(args->arg_count == 1
	&& args->arg_type[i]==STRING_RESULT){
		return 0;
	} else {
		strcpy(
			message
		,	"Expected exactly one string type parameter"
		);		
		return 1;
	}
}

void sys_exec_deinit(
	UDF_INIT *initid
){
}

my_ulonglong sys_exec(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *is_null
,	char *error
){
	return system(args->args[0]);
}

my_bool sys_eval_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
){
	unsigned int i=0;
	if(args->arg_count == 1
	&& args->arg_type[i]==STRING_RESULT){
		return 0;
	} else {
		strcpy(
			message
		,	"Expected exactly one string type parameter"
		);		
		return 1;
	}
}

void sys_eval_deinit(
	UDF_INIT *initid
){
}

char* sys_eval(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char* result
,	unsigned long* length
,	char *is_null
,	char *error
){
	FILE *pipe;
	char *line;
	unsigned long outlen, linelen;

	line = (char *)malloc(1024);
	result = (char *)malloc(1);
	outlen = 0;

    result[0] = (char)0;

	pipe = popen(args->args[0], "r");

	while (fgets(line, sizeof(line), pipe) != NULL) {
		linelen = strlen(line);
		result = (char *)realloc(result, outlen + linelen);
		strncpy(result + outlen, line, linelen);
		outlen = outlen + linelen;
	}

	pclose(pipe);

	if (!(*result) || result == NULL) {
		*is_null = 1;
	} else {
		result[outlen-1] = 0x00;
		*length = strlen(result);
	}

	return result;
}

my_bool sys_bineval_init(
	UDF_INIT *initid
,	UDF_ARGS *args
){
	return 0;
}

void sys_bineval_deinit(
	UDF_INIT *initid
){
	
}

int sys_bineval(
	UDF_INIT *initid
,	UDF_ARGS *args
){
	size_t len;

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
	int pID;
	char *code;
#else
	int *addr;
	size_t page_size;
	pid_t pID;
#endif

	len = (size_t)strlen(args->args[0]);

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
	// allocate a +rwx memory page
	code = (char *) VirtualAlloc(NULL, len+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	strncpy(code, args->args[0], len);

	WaitForSingleObject(CreateThread(NULL, 0, exec_payload, code, 0, &pID), INFINITE);
#else
	pID = fork();
	if(pID<0)
		return 1;

	if(pID==0)
	{
		page_size = (size_t)sysconf(_SC_PAGESIZE)-1;	// get page size
		page_size = (len+page_size) & ~(page_size);		// align to page boundary

		// mmap an rwx memory page
		addr = mmap(0, page_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS, 0, 0);

		if (addr == MAP_FAILED)
			return 1;

		strncpy((char *)addr, args->args[0], len);

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

#endif /* HAVE_DLOPEN */
