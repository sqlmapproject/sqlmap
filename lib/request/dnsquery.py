#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

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
        retval = ""

        if self._query:
            retval += self._raw[:2] + "\x81\x80"
            retval += self._raw[4:6] + self._raw[4:6] + "\x00\x00\x00\x00"      # Questions and Answers Counts
            retval += self._raw[12:]                                            # Original Domain Name Question
            retval += "\xc0\x0c"                                                # Pointer to domain name
            retval += "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"                # Response type, ttl and resource data length -> 4 bytes
            retval += "".join(chr(int(_)) for _ in resolution.split('.'))       # 4 bytes of IP

        return retval
