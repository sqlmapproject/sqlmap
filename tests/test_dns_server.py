#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The DNS server used for DNS-exfiltration (lib/request/dns.py): raw packet parsing
(DNSQuery), fake A-record response crafting, the pop(prefix, suffix) accounting, and
- importantly - resilience: a single malformed packet or a transient send error must
NOT kill the server thread (which would silently lose all further exfiltration).
"""

import collections
import os
import socket
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from lib.core.settings import MAX_DNS_REQUESTS
from lib.request.dns import DNSQuery, DNSServer


def build_query(name, tid=b"\x12\x34", qtype=1):
    """Minimal standard (opcode 0) DNS query packet for L{name} (qtype 1=A, 28=AAAA, ...)"""
    pkt = tid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    for label in name.split("."):
        if label:
            pkt += struct.pack("B", len(label)) + label.encode()
    return pkt + b"\x00" + struct.pack(">H", qtype) + b"\x00\x01"


class _HighPortDNSServer(DNSServer):
    """Real DNSServer logic, bound on an ephemeral high port (no root, no :53 probe).

    Binds to port 0 and reads the kernel-chosen port back via getsockname() (same pattern
    as tests/test_dns_engine.py) so concurrent/repeated runs never collide on a hardcoded
    port. The actual port is exposed as L{self.port}.
    """
    def __init__(self, sock=None, maxlen=MAX_DNS_REQUESTS):
        self._requests = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
        self._socket = sock
        self.port = self._socket.getsockname()[1]
        self._running = False
        self._initialized = False

    def close(self):
        self._running = False
        try:
            self._socket.close()
        except socket.error:
            pass


# Maximum time (seconds) to wait for the daemon server thread to come up, or for a sent
# query to be recorded, before failing loudly instead of spinning/sleeping forever.
WAIT_TIMEOUT = 5.0


def _wait_initialized(srv, timeout=WAIT_TIMEOUT):
    """Bounded wait for the server thread to flip _initialized; fail fast if it never does."""
    deadline = time.time() + timeout
    while not srv._initialized:
        if time.time() > deadline:
            raise RuntimeError("DNS server failed to initialize within %.1fs" % timeout)
        time.sleep(0.01)


def _wait_recorded(srv, token, timeout=WAIT_TIMEOUT):
    """Bounded wait until L{token} appears in a recorded request; False on timeout."""
    if hasattr(token, "encode"):
        token = token.encode()
    deadline = time.time() + timeout
    while time.time() <= deadline:
        with srv._lock:
            if any(token in r for r in srv._requests):
                return True
        time.sleep(0.01)
    return False


def _wait_popped(srv, prefix, suffix, timeout=WAIT_TIMEOUT):
    """Bounded wait until pop(prefix, suffix) yields a value; returns it or None on timeout."""
    deadline = time.time() + timeout
    while time.time() <= deadline:
        popped = srv.pop(prefix, suffix)
        if popped:
            return popped
        time.sleep(0.01)
    return None


class _SendFailOnceSocket(object):
    """Wraps a real UDP socket; first sendto() raises (simulated transient failure)"""
    def __init__(self, real):
        self._real = real
        self._sends = 0

    def recvfrom(self, *a, **k):
        return self._real.recvfrom(*a, **k)

    def sendto(self, *a, **k):
        self._sends += 1
        if self._sends == 1:
            raise RuntimeError("simulated transient sendto failure")
        return self._real.sendto(*a, **k)

    def __getattr__(self, name):
        return getattr(self._real, name)


class TestDNSQuery(unittest.TestCase):
    def test_parses_data_bearing_name(self):
        q = DNSQuery(build_query("pre.deadbeef.suf.exfil.test"))
        self.assertEqual(q._query, b"pre.deadbeef.suf.exfil.test.")

    def test_empty_and_short_packets_do_not_raise(self):
        for raw in (b"", b"\x00", b"\x12", b"\x12\x34", b"\x12\x34\x01\x20"):
            self.assertEqual(DNSQuery(raw)._query, b"")  # no exception, empty query

    def test_unterminated_name_does_not_raise(self):
        # a length byte that runs past the buffer, with no null terminator
        pkt = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x20" + b"abc"
        DNSQuery(pkt)  # must not raise (slicing past end yields b"", ord guards)

    def test_response_is_valid_A_record(self):
        q = DNSQuery(build_query("x.y.z", tid=b"\xab\xcd"))
        resp = q.response("127.0.0.1")
        self.assertEqual(resp[:2], b"\xab\xcd")                 # transaction id echoed
        self.assertEqual(resp[2:4], b"\x85\x80")                # standard response, no error
        ip = ".".join(str(b if isinstance(b, int) else ord(b)) for b in resp[-4:])
        self.assertEqual(ip, "127.0.0.1")

    def test_empty_query_yields_empty_response(self):
        self.assertEqual(DNSQuery(b"\x00").response("127.0.0.1"), b"")


class TestDNSServerRoundTrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = _HighPortDNSServer()
        cls.srv.run()
        _wait_initialized(cls.srv)

    @classmethod
    def tearDownClass(cls):
        srv = getattr(cls, "srv", None)
        if srv is not None:
            srv.close()
            cls.srv = None

    def _send(self, name):
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.settimeout(3)
        c.sendto(build_query(name), ("127.0.0.1", self.srv.port))
        try:
            c.recvfrom(512)
        except socket.timeout:
            pass
        finally:
            c.close()
        return _wait_recorded(self.srv, name)

    def test_roundtrip_and_pop(self):
        self.assertTrue(self._send("aaa.cafe.bbb.exfil.test"))
        self.assertIsNone(self.srv.pop("zzz", "yyy"))                 # wrong boundaries
        self.assertIsNotNone(self.srv.pop("aaa", "bbb"))             # correct boundaries
        self.assertIsNone(self.srv.pop("aaa", "bbb"))               # consumed only once

    def test_non_a_query_type_still_recorded(self):
        # a DBMS resolver may emit AAAA (28) / TXT (16) lookups - the exfiltrated name is in the
        # labels regardless of qtype, and the server records before crafting the (A) response
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.settimeout(2)
        c.sendto(build_query("ggg.beef.hhh.exfil.test", qtype=28), ("127.0.0.1", self.srv.port))
        try:
            c.recvfrom(512)
        except socket.timeout:
            pass
        finally:
            c.close()
        if not _wait_popped(self.srv, "ggg", "hhh"):
            self.fail("AAAA-type query was not recorded (exfil would be lost for AAAA-resolving DBMSes)")


class TestDNSServerMemoryBound(unittest.TestCase):
    """The server records every received query (it listens on :53); only matching ones are
    popped. Unrelated/stray traffic and resolver retries must not grow memory without bound."""

    def test_requests_are_bounded_and_recent_kept(self):
        srv = _HighPortDNSServer(maxlen=50)
        self.addCleanup(srv.close)
        srv.run()
        _wait_initialized(srv)
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(200):                      # flood well past the bound
            c.sendto(build_query("noise%d.unrelated.test" % i), ("127.0.0.1", srv.port))
        c.close()
        # a legit exfil query right after the flood must still be capturable
        c2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c2.settimeout(2)
        c2.sendto(build_query("ppp.d00d.qqq.exfil.test"), ("127.0.0.1", srv.port))
        try:
            c2.recvfrom(512)
        except socket.timeout:
            pass
        finally:
            c2.close()
        popped = _wait_popped(srv, "ppp", "qqq")
        with srv._lock:
            n = len(srv._requests)
        self.assertLessEqual(n, 50, "request buffer exceeded its bound (%d)" % n)
        self.assertIsNotNone(popped, "a fresh exfil query was lost after a flood of stray traffic")


class TestDNSServerResilience(unittest.TestCase):
    def _make(self, sock=None):
        srv = _HighPortDNSServer(sock=sock)
        self.addCleanup(srv.close)
        srv.run()
        _wait_initialized(srv)
        return srv

    def _query(self, port, name):
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.settimeout(1)
        c.sendto(build_query(name), ("127.0.0.1", port))
        try:
            c.recvfrom(512)
        except socket.timeout:
            pass
        finally:
            c.close()

    def _recorded(self, srv, token):
        return _wait_recorded(srv, token)

    def test_survives_transient_send_error(self):
        # ephemeral bind, then wrap the bound socket so its first sendto() raises
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        srv = self._make(sock=_SendFailOnceSocket(s))
        self._query(srv.port, "aaa.11.bbb.exfil.test")   # first sendto raises
        self._query(srv.port, "ccc.22.ddd.exfil.test")   # must still be served
        self.assertTrue(self._recorded(srv, "ccc.22.ddd"),
                        "DNS server died after one failing sendto (lost subsequent exfil)")
        self.assertTrue(srv._running)

    def test_survives_malformed_packets(self):
        srv = self._make()
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for junk in (b"", b"\x00", b"\xff" * 7, b"\x12\x34\x01\x00\x00\x01" + b"\x20abc"):
            c.sendto(junk, ("127.0.0.1", srv.port))
        c.close()
        self._query(srv.port, "ok.33.fine.exfil.test")
        self.assertTrue(self._recorded(srv, "ok.33.fine"),
                        "DNS server died on a malformed packet")


class TestDNSServerConcurrency(unittest.TestCase):
    """Under --threads, many workers fire DNS queries and call pop() while the server thread
    appends - all guarded by one lock. Each worker must get back exactly its own data."""

    @classmethod
    def setUpClass(cls):
        cls.srv = _HighPortDNSServer()
        cls.srv.run()
        _wait_initialized(cls.srv)

    @classmethod
    def tearDownClass(cls):
        srv = getattr(cls, "srv", None)
        if srv is not None:
            srv.close()
            cls.srv = None

    def test_concurrent_send_and_pop_no_crosstalk(self):
        import binascii, re
        N = 12
        errors = []

        def worker(i):
            # distinct boundary labels per worker (DNS boundary alphabet = letters, no a-f/digits)
            prefix = "gg" + chr(ord("g") + i)
            suffix = "mm" + chr(ord("g") + i)
            secret = ("worker-%02d-secret" % i).encode()
            host = "%s.%s.%s.exfil.test" % (prefix, binascii.hexlify(secret).decode(), suffix)
            c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c.settimeout(2)
            try:
                c.sendto(build_query(host), ("127.0.0.1", self.srv.port))
                try:
                    c.recvfrom(512)
                except socket.timeout:
                    pass
            finally:
                c.close()
            got = _wait_popped(self.srv, prefix, suffix)
            if not got:
                errors.append("worker %d: never popped its query" % i); return
            m = re.search(r"%s\.(?P<r>.+?)\.%s" % (prefix, suffix), got, re.I)
            if not m or binascii.unhexlify(m.group("r")) != secret:
                errors.append("worker %d: cross-talk/corruption got=%r" % (i, got))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], "concurrency failures: %s" % errors)
        # every queued request consumed exactly once -> nothing left behind
        self.assertEqual(self.srv.pop("gg" + chr(ord("g")), "mm" + chr(ord("g"))), None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
