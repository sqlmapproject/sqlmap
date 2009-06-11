#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""



import errno
import os
import sys
import time

from lib.core.settings import IS_WIN


if IS_WIN is not True:
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
