#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
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

    def run(self):
        def _():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("", 53))

            try:
                while True:
                    data, addr = s.recvfrom(1024)
                    _ = DNSQuery(data)
                    s.sendto(_.response("127.0.0.1"), addr)
                    self._lock.acquire()
                    self._requests.append(_._query)
                    self._lock.release()
            finally:
                s.close()

        thread = threading.Thread(target=_)
        thread.start()

if __name__ == "__main__":
    server = DNSServer()
    try:
        server.run()
        while True:
            server._lock.acquire()
            for _ in server._requests[:]:
                print _
            server._requests = []
            server._lock.release()
            time.sleep(1)
    except KeyboardInterrupt:
        os._exit(0)
