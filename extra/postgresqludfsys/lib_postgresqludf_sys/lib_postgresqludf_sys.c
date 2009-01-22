/* 
	lib_postgresqludf_sys - a library with miscellaneous (operating) system level functions
	Copyright (C) 2009  Bernardo Damele A. G.
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

#include <stdlib.h>
#include <postgres.h>
#include <fmgr.h>

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

PG_FUNCTION_INFO_V1(sys_exec);
Datum sys_exec(PG_FUNCTION_ARGS) {
	text *argv0 = PG_GETARG_TEXT_P(0);
	int32 argv0_size;
	int32 result = 0;
	char *command;

	argv0_size = VARSIZE(argv0) - VARHDRSZ;
	command = (char *)palloc(argv0_size + 1);

	memcpy(command, VARDATA(argv0), argv0_size);
	command[argv0_size] = '\0';

	/*
	Only if you want to log
	elog(NOTICE, "Command execution: %s", command);
	*/

	result = system(command);
	pfree(command);

	PG_FREE_IF_COPY(argv0, 0);
	PG_RETURN_INT32(result);
}

PG_FUNCTION_INFO_V1(sys_eval);
Datum sys_eval(PG_FUNCTION_ARGS) {
	text *argv0 = PG_GETARG_TEXT_P(0);
	text *result_text;
	int32 argv0_size;
	char *command;
	char *result;
	FILE *pipe;
	char line[1024];
	int32 outlen, linelen;

	argv0_size = VARSIZE(argv0) - VARHDRSZ;
	command = (char *)palloc(argv0_size + 1);

	memcpy(command, VARDATA(argv0), argv0_size);
	command[argv0_size] = '\0';

	/*
	Only if you want to log
	elog(NOTICE, "Command evaluated: %s", command);
	*/

	result = malloc(1);
	outlen = 0;

	pipe = popen(command, "r");

	while (fgets(line, sizeof(line), pipe) != NULL) {
		linelen = strlen(line);
		result = realloc(result, outlen + linelen);
		strncpy(result + outlen, line, linelen);
		outlen = outlen + linelen;
	}

	pclose(pipe);

	if (*result) {
		result[outlen] = 0x00;
	}

	result_text = (text *)palloc(VARHDRSZ + strlen(result));
	SET_VARSIZE(result_text, VARHDRSZ + strlen(result));
	memcpy(VARDATA(result_text), result, strlen(result));

	PG_RETURN_POINTER(result_text);
}
