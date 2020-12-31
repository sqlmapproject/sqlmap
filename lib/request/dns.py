#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import binascii
import os
import re
import socket
import struct
import threading
import time

class DNSQuery(object):
    """
    >>> DNSQuery(b'|K\\x01 \\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x01\\x03www\\x06google\\x03com\\x00\\x00\\x01\\x00\\x01\\x00\\x00)\\x10\\x00\\x00\\x00\\x00\\x00\\x00\\x0c\\x00\\n\\x00\\x08O4|Np!\\x1d\\xb3')._query == b"www.google.com."
    True
    >>> DNSQuery(b'\\x00')._query == b""
    True
    """

    def __init__(self, raw):
        self._raw = raw
        self._query = b""

        try:
            type_ = (ord(raw[2:3]) >> 3) & 15                   # Opcode bits

            if type_ == 0:                                      # Standard query
                i = 12
                j = ord(raw[i:i + 1])

                while j != 0:
                    self._query += raw[i + 1:i + j + 1] + b'.'
                    i = i + j + 1
                    j = ord(raw[i:i + 1])
        except TypeError:
            pass

    def response(self, resolution):
        """
        Crafts raw DNS resolution response packet
        """

        retVal = b""

        if self._query:
            retVal += self._raw[:2]                                                         # Transaction ID
            retVal += b"\x85\x80"                                                           # Flags (Standard query response, No error)
            retVal += self._raw[4:6] + self._raw[4:6] + b"\x00\x00\x00\x00"                 # Questions and Answers Counts
            retVal += self._raw[12:(12 + self._raw[12:].find(b"\x00") + 5)]                 # Original Domain Name Query
            retVal += b"\xc0\x0c"                                                           # Pointer to domain name
            retVal += b"\x00\x01"                                                           # Type A
            retVal += b"\x00\x01"                                                           # Class IN
            retVal += b"\x00\x00\x00\x20"                                                   # TTL (32 seconds)
            retVal += b"\x00\x04"                                                           # Data length
            retVal += b"".join(struct.pack('B', int(_)) for _ in resolution.split('.'))     # 4 bytes of IP

        return retVal

class DNSServer(object):
    """
    Used for making fake DNS resolution responses based on received
    raw request

    Reference(s):
        http://code.activestate.com/recipes/491264-mini-fake-dns-server/
        https://code.google.com/p/marlon-tools/source/browse/tools/dnsproxy/dnsproxy.py
    """

    def __init__(self):
        self._check_localhost()
        self._requests = []
        self._lock = threading.Lock()

        try:
            self._socket = socket._orig_socket(socket.AF_INET, socket.SOCK_DGRAM)
        except AttributeError:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("", 53))
        self._running = False
        self._initialized = False

    def _check_localhost(self):
        response = b""

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("", 53))
            s.send(binascii.unhexlify("6509012000010000000000010377777706676f6f676c6503636f6d00000100010000291000000000000000"))  # A www.google.com
            response = s.recv(512)
        except:
            pass
        finally:
            if response and b"google" in response:
                raise socket.error("another DNS service already running on '0.0.0.0:53'")

    def pop(self, prefix=None, suffix=None):
        """
        Returns received DNS resolution request (if any) that has given
        prefix/suffix combination (e.g. prefix.<query result>.suffix.domain)
        """

        retVal = None

        if prefix and hasattr(prefix, "encode"):
            prefix = prefix.encode()

        if suffix and hasattr(suffix, "encode"):
            suffix = suffix.encode()

        with self._lock:
            for _ in self._requests:
                if prefix is None and suffix is None or re.search(b"%s\\..+\\.%s" % (prefix, suffix), _, re.I):
                    self._requests.remove(_)
                    retVal = _.decode()
                    break

        return retVal

    def run(self):
        """
        Runs a DNSServer instance as a daemon thread (killed by program exit)
        """

        def _():
            try:
                self._running = True
                self._initialized = True

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
    server = None
    try:
        server = DNSServer()
        server.run()

        while not server._initialized:
            time.sleep(0.1)

        while server._running:
            while True:
                _ = server.pop()

                if _ is None:
                    break
                else:
                    print("[i] %s" % _)

            time.sleep(1)

    except socket.error as ex:
        if 'Permission' in str(ex):
            print("[x] Please run with sudo/Administrator privileges")
        else:
            raise
    except KeyboardInterrupt:
        os._exit(0)
    finally:
        if server:
            server._running = False
