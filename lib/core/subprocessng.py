#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import errno
import os
import subprocess
import time

from lib.core.compat import buffer
from lib.core.convert import getBytes
from lib.core.settings import IS_WIN

if IS_WIN:
    try:
        from win32file import ReadFile, WriteFile
        from win32pipe import PeekNamedPipe
    except ImportError:
        pass
    import msvcrt
else:
    import select
    import fcntl

def blockingReadFromFD(fd):
    # Quick twist around original Twisted function
    # Blocking read from a non-blocking file descriptor
    output = b""

    while True:
        try:
            output += os.read(fd, 8192)
        except (OSError, IOError) as ioe:
            if ioe.args[0] in (errno.EAGAIN, errno.EINTR):
                # Uncomment the following line if the process seems to
                # take a huge amount of cpu time
                # time.sleep(0.01)
                continue
            else:
                raise
        break

    if not output:
        raise EOFError("fd %s has been closed." % fd)

    return output

def blockingWriteToFD(fd, data):
    # Another quick twist
    while True:
        try:
            data_length = len(data)
            wrote_data = os.write(fd, data)
        except (OSError, IOError) as io:
            if io.errno in (errno.EAGAIN, errno.EINTR):
                continue
            else:
                raise

        if wrote_data < data_length:
            blockingWriteToFD(fd, data[wrote_data:])

        break

# the following code is taken from http://code.activestate.com/recipes/440554-module-to-allow-asynchronous-subprocess-use-on-win/
class Popen(subprocess.Popen):
    def recv(self, maxsize=None):
        return self._recv('stdout', maxsize)

    def recv_err(self, maxsize=None):
        return self._recv('stderr', maxsize)

    def send_recv(self, input='', maxsize=None):
        return self.send(input), self.recv(maxsize), self.recv_err(maxsize)

    def get_conn_maxsize(self, which, maxsize):
        if maxsize is None:
            maxsize = 1024
        elif maxsize < 1:
            maxsize = 1
        return getattr(self, which), maxsize

    def _close(self, which):
        getattr(self, which).close()
        setattr(self, which, None)

    if IS_WIN:
        def send(self, input):
            if not self.stdin:
                return None

            try:
                x = msvcrt.get_osfhandle(self.stdin.fileno())
                (_, written) = WriteFile(x, input)
            except ValueError:
                return self._close('stdin')
            except Exception as ex:
                if getattr(ex, "args", None) and ex.args[0] in (109, errno.ESHUTDOWN):
                    return self._close('stdin')
                raise

            return written

        def _recv(self, which, maxsize):
            conn, maxsize = self.get_conn_maxsize(which, maxsize)
            if conn is None:
                return None

            try:
                x = msvcrt.get_osfhandle(conn.fileno())
                (read, nAvail, _) = PeekNamedPipe(x, 0)
                if maxsize < nAvail:
                    nAvail = maxsize
                if nAvail > 0:
                    (_, read) = ReadFile(x, nAvail, None)
            except (ValueError, NameError):
                return self._close(which)
            except Exception as ex:
                if getattr(ex, "args", None) and ex.args[0] in (109, errno.ESHUTDOWN):
                    return self._close(which)
                raise

            if self.universal_newlines:
                read = self._translate_newlines(read)
            return read
    else:
        def send(self, input):
            if not self.stdin:
                return None

            if not select.select([], [self.stdin], [], 0)[1]:
                return 0

            try:
                written = os.write(self.stdin.fileno(), input)
            except OSError as ex:
                if ex.args[0] == errno.EPIPE:  # broken pipe
                    return self._close('stdin')
                raise

            return written

        def _recv(self, which, maxsize):
            conn, maxsize = self.get_conn_maxsize(which, maxsize)
            if conn is None:
                return None

            flags = fcntl.fcntl(conn, fcntl.F_GETFL)
            if not conn.closed:
                fcntl.fcntl(conn, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            try:
                if not select.select([conn], [], [], 0)[0]:
                    return ''

                r = conn.read(maxsize)
                if not r:
                    return self._close(which)

                if self.universal_newlines:
                    r = self._translate_newlines(r)
                return r
            finally:
                if not conn.closed:
                    fcntl.fcntl(conn, fcntl.F_SETFL, flags)

def recv_some(p, t=.1, e=1, tr=5, stderr=0):
    if tr < 1:
        tr = 1
    x = time.time() + t
    y = []
    r = ''
    if stderr:
        pr = p.recv_err
    else:
        pr = p.recv
    while time.time() < x or r:
        r = pr()
        if r is None:
            break
        elif r:
            y.append(r)
        else:
            time.sleep(max((x - time.time()) / tr, 0))
    return b''.join(y)

def send_all(p, data):
    if not data:
        return

    data = getBytes(data)

    while len(data):
        sent = p.send(data)
        if not isinstance(sent, int):
            break
        data = buffer(data[sent:])
