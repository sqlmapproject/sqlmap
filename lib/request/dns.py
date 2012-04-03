#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re
import socket
import threading
import time

class DNSQuery:
    """
    Used for making fake DNS resolution responses based on received
    raw request

    Reference(s):
        http://code.activestate.com/recipes/491264-mini-fake-dns-server/
        https://code.google.com/p/marlon-tools/source/browse/tools/dnsproxy/dnsproxy.py
    """

    def __init__(self, raw):
        self._raw = raw
        self._query = ""

        type_ = (ord(raw[2]) >> 3) & 15                 # Opcode bits
        if type_ == 0:                                  # Standard query
            i = 12
            j = ord(raw[i])
            while j != 0:
                self._query += raw[i+1:i+j+1] + '.'
                i = i + j + 1
                j = ord(raw[i])

    def response(self, resolution):
        retVal = ""

        if self._query:
            retVal += self._raw[:2] + "\x81\x80"
            retVal += self._raw[4:6] + self._raw[4:6] + "\x00\x00\x00\x00"      # Questions and Answers Counts
            retVal += self._raw[12:]                                            # Original Domain Name Question
            retVal += "\xc0\x0c"                                                # Pointer to domain name
            retVal += "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"                # Response type, ttl and resource data length -> 4 bytes
            retVal += "".join(chr(int(_)) for _ in resolution.split('.'))       # 4 bytes of IP

        return retVal

class DNSServer:
    def __init__(self):
        self._requests = []
        self._lock = threading.Lock()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("", 53))
        self._running = False

    def pop(self, prefix=None, suffix=None):
        retVal = None
        with self._lock:
            for _ in self._requests:
                if prefix is None and suffix is None or re.search("%s\..+\.%s" % (prefix, suffix), _, re.I):
                    retVal = _
                    self._requests.remove(_)
                    break
        return retVal

    def run(self):
        def _():
            try:
                self._running = True
                while True:
                    data, addr = self._socket.recvfrom(1024)
                    _ = DNSQuery(data)
                    self._socket.sendto(_.response("127.0.0.1"), addr)
                    with self._lock:
                        self._requests.append(_._query)
            except KeyboardInterrupt:
                raise
            finally:
                self._running = False

        thread = threading.Thread(target=_)
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    try:
        server = DNSServer()
        server.run()
        while server._running:
            while True:
                _ = server.pop()
                if _ is None:
                    break
                else:
                    print "[i] %s" % _
            time.sleep(1)
    except socket.error, ex:
        if 'Permission' in str(ex):
            print "[x] Please run with sudo/Administrator privileges"
        else:
            raise
    except KeyboardInterrupt:
        os._exit(0)
    finally:
        server._running = False
