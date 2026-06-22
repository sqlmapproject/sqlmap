#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import binascii
import collections
import errno
import os
import re
import socket
import struct
import threading
import time

try:
    from lib.core.settings import MAX_DNS_REQUESTS
except ImportError:
    MAX_DNS_REQUESTS = 1000     # fallback so this module stays runnable standalone

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
            if len(raw) < 13:
                return

            type_ = (ord(raw[2:3]) >> 3) & 15                   # Opcode bits

            if type_ == 0:                                      # Standard query
                i = 12
                labels = []

                while True:
                    if i >= len(raw):
                        return

                    j = ord(raw[i:i + 1])

                    if j == 0:
                        break

                    i += 1

                    if i + j > len(raw):
                        return

                    labels.append(raw[i:i + j])
                    i += j

                if labels:
                    self._query = b".".join(labels) + b'.'
        except (TypeError, ValueError, IndexError):
            self._query = b""

    def response(self, resolution):
        """
        Crafts raw DNS resolution response packet
        """

        retVal = b""

        if self._query:
            end = self._raw[12:].find(b"\x00")

            if end < 0 or len(self._raw) < 12 + end + 5:
                return retVal

            retVal += self._raw[:2]                                                         # Transaction ID
            retVal += b"\x85\x80"                                                           # Flags (Standard query response, No error)
            retVal += self._raw[4:6] + self._raw[4:6] + b"\x00\x00\x00\x00"                 # Questions and Answers Counts
            retVal += self._raw[12:(12 + end + 5)]                                          # Original Domain Name Query
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
        https://code.activestate.com/recipes/491264-mini-fake-dns-server/
        https://web.archive.org/web/20150418152405/https://code.google.com/p/marlon-tools/source/browse/tools/dnsproxy/dnsproxy.py
    """

    def __init__(self):
        self._check_localhost()
        self._requests = collections.deque(maxlen=MAX_DNS_REQUESTS)
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
        s = None

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect(("", 53))
            s.send(binascii.unhexlify("6509012000010000000000010377777706676f6f676c6503636f6d00000100010000291000000000000000"))  # A www.google.com
            response = s.recv(512)
        except:
            pass
        finally:
            if s:
                s.close()

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
            def _is_udp_connreset(ex):
                return getattr(ex, "winerror", None) == 10054 or getattr(ex, "errno", None) in (errno.ECONNRESET, 10054)

            try:
                self._running = True
                self._initialized = True

                try:
                    if hasattr(socket, "SIO_UDP_CONNRESET") and hasattr(self._socket, "ioctl"):
                        # Windows reports ICMP "port unreachable" for UDP as WSAECONNRESET on
                        # recvfrom(). DNS clients in tests and in the wild can disappear before
                        # reading our fake response; that must not kill the server thread.
                        self._socket.ioctl(socket.SIO_UDP_CONNRESET, False)
                except Exception:
                    pass

                while True:
                    try:
                        data, addr = self._socket.recvfrom(1024)
                    except KeyboardInterrupt:
                        raise
                    except socket.error as ex:
                        if _is_udp_connreset(ex):
                            continue
                        break       # socket closed/broken - stop serving (e.g. program exit)
                    except Exception:
                        break       # socket closed/broken - stop serving (e.g. program exit)

                    # Note: a single malformed packet or a transient send error must NOT kill the
                    # server thread (otherwise all subsequent DNS exfiltration is silently lost).
                    # The query is recorded BEFORE responding, so the exfiltrated data is captured
                    # even if crafting/sending the (fake) resolution response fails.
                    try:
                        _ = DNSQuery(data)

                        if not _._query:
                            continue

                        with self._lock:
                            self._requests.append(_._query)

                        response = _.response("127.0.0.1")

                        if response:
                            self._socket.sendto(response, addr)
                    except KeyboardInterrupt:
                        raise
                    except Exception:
                        pass

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
