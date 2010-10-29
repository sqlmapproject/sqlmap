#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import errno
import os
import sys
import time

from lib.core.common import dataToStdout
from lib.core.settings import IS_WIN

if not IS_WIN:
    import fcntl

    if (sys.hexversion >> 16) >= 0x202:
        FCNTL = fcntl
    else:
        import FCNTL

def blockingReadFromFD(fd):
    # Quick twist around original Twisted function
    # Blocking read from a non-blocking file descriptor
    output = ""

    while True:
        try:
            output += os.read(fd, 8192)
        except (OSError, IOError), ioe:
            if ioe.args[0] in (errno.EAGAIN, errno.EINTR):
                # Uncomment the following line if the process seems to
                # take a huge amount of cpu time
                # time.sleep(0.01)
                continue 
            else:
                raise
        break

    if not output:
        raise EOFError, "fd %s has been closed." % fd 

    return output

def blockingWriteToFD(fd, data):
    # Another quick twist
    while True:
        try:
            data_length = len(data)
            wrote_data  = os.write(fd, data)
        except (OSError, IOError), io:
            if io.errno in (errno.EAGAIN, errno.EINTR):
                continue    
            else:
                raise 

        if wrote_data < data_length:
            blockingWriteToFD(fd, data[wrote_data:])

        break

def setNonBlocking(fd):
    """
    Make a file descriptor non-blocking
    """

    if IS_WIN is not True:
        flags = fcntl.fcntl(fd, FCNTL.F_GETFL)
        flags = flags | os.O_NONBLOCK
        fcntl.fcntl(fd, FCNTL.F_SETFL, flags)

def pollProcess(process):
    while True:
        dataToStdout(".")
        time.sleep(1)

        returncode = process.poll()

        if returncode is not None:
            if returncode == 0:
                dataToStdout(" done\n")
            elif returncode < 0:
                dataToStdout(" process terminated by signal %d\n" % returncode)
            elif returncode > 0:
                dataToStdout(" quit unexpectedly with return code %d\n" % returncode)

            break
