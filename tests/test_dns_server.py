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
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from lib.core.settings import MAX_DNS_REQUESTS
from lib.request.dns import DNSQuery, DNSServer, InteractshDNSServer


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


def _stop_client_poller(client):
    """Best-effort shutdown of a client's single background poller, used by stubbed close()
    so test teardown never joins a live thread or reaches the network."""
    poller = getattr(client, "_poller", None)
    if poller is not None:
        try:
            poller.stop()
        except Exception:
            pass


def _start_test_poller(client):
    """Start a real InteractshPoller around a fake poll() without requiring pycryptodome.

    Interactsh._ensurePoller() intentionally no-ops when crypto is unavailable because a real
    interactsh /poll response cannot then be decrypted. These tests replace poll() with an
    already-decoded in-memory fake, so their queue/poller behavior should not depend on whether
    the test interpreter happens to have Crypto installed (notably PyPy 2.7 in CI).
    """
    from lib.request.interactsh import InteractshPoller
    poller = getattr(client, "_poller", None)
    if poller is None:
        client._poller = poller = InteractshPoller(client)
    poller.start()
    return poller


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


class TestInteractshDNSServer(unittest.TestCase):
    """The interactsh-backed DNS collector must present the same pop(prefix, suffix)
    accounting as DNSServer, matching only prefix.<result>.suffix names and never
    returning the same captured lookup twice."""

    def _collector(self, names, deadline=None, start_poller=True):
        """Build an InteractshDNSServer (bypassing __init__) over a fake client.

        The fake drives the real poller-aware consume path (production code, not a stub), returns
        its records ONCE destructively - exactly as a real interactsh endpoint drains storage -
        and, because close()/_request() are stubbed, can never reach the network at teardown.
        ``deadline`` sets this instance's pop() search budget (seconds); ``start_poller`` runs the
        single background consumer, as normal registered operation would.
        """
        from lib.request.interactsh import Interactsh
        client = Interactsh.__new__(Interactsh)   # bypass network __init__
        client.registered = True
        client.correlationId = "corr0000000000000nnc"
        client.server = "oast.fun"
        client.secret = "test-secret"
        client._pollerLock = threading.Lock()   # __init__ is bypassed, so set it explicitly
        client._stopping = False               # __init__ sets it; set it here too
        client._dnsNonce = None  # lets the real dnsDomain() run (lazy-initialises it)

        names_batch = list(names)

        def poll():
            # return the whole batch once, then nothing - mirrors an interactsh endpoint
            # draining its pending storage in a single /poll response
            if names_batch:
                batch = [{"protocol": "dns", "full-id": n, "unique-id": n} for n in names_batch]
                del names_batch[:]
                return batch
            return []
        client.poll = poll

        for meth in ("_ensurePoller", "_consume", "_safeSelector"):
            setattr(client, meth, types.MethodType(getattr(Interactsh, meth), client))

        # teardown (srv.stop() -> client.stop() -> close) must never touch the network
        client.close = lambda: _stop_client_poller(client)
        client._request = lambda *a, **k: None

        srv = InteractshDNSServer.__new__(InteractshDNSServer)
        srv._client = client
        srv.domain = srv._client.dnsDomain()
        srv._seen = set()
        srv._running = True
        srv._initialized = True
        srv._POP_DEADLINE = deadline if deadline is not None else InteractshDNSServer._POP_DEADLINE
        self.addCleanup(srv.stop)   # stops the poller then deregisters (close() is network-stubbed)
        if start_poller:
            poller = _start_test_poller(srv._client)
            t = time.time() + 2.0
            while not poller._queue and time.time() < t:   # wait for the destructive batch to stage
                time.sleep(0.01)
        return srv

    def test_pop_matches_prefix_suffix_and_dedups(self):
        names = ["aaa.5345435245540a.zzz.corr0000000000000nnc", "unrelated.corr0000000000000nnc"]
        srv = self._collector(names)
        got = srv.pop("aaa", "zzz")
        self.assertEqual(got, "aaa.5345435245540a.zzz.corr0000000000000nnc")
        self.assertIsNone(srv.pop("aaa", "zzz", deadline=0))   # consumed only once (snapshot)
        srv.stop()

    def test_pop_does_not_consume_a_sharing_http_record(self):
        """Regression for the cross-consumer loss the shared poller was introduced to prevent.

        pop() and httpRequests() draw from the same background poller queue. If pop() does not
        verify the record's protocol, a queued HTTP interaction whose full-id matches the DNS
        window would be returned as though it were a DNS lookup, and the HTTP consumer would
        then lose it. Both records here share the SAME full-id; pop() must return the DNS name
        only and leave the HTTP record for httpRequests()."""
        from lib.request.interactsh import Interactsh
        dns_full = "aaa.deadbeef.bbb.corr0000000000000nnc"
        http_full = "aaa.deadbeef.bbb.corr0000000000000nnc"   # shared full-id with the DNS record
        recs = [
            {"protocol": "dns", "full-id": dns_full, "unique-id": dns_full,
             "remote-address": "1.1.1.1", "raw-request": "QUERY"},
            {"protocol": "http", "full-id": http_full,
             "raw-request": "GET /?cafebabe=1 HTTP/1.1", "remote-address": "2.2.2.2"},
        ]
        client = Interactsh.__new__(Interactsh)   # bypass network __init__
        client.registered = True
        client.correlationId = "corr0000000000000nnc"
        client.server = "oast.fun"
        client.secret = "test-secret"
        client._pollerLock = threading.Lock()        # __init__ is bypassed, so set it explicitly
        client._stopping = False                     # __init__ sets it; set it here too
        client._dnsNonce = None

        rec_batch = list(recs)

        def poll():
            # return the whole batch once, then nothing - mirrors an interactsh endpoint
            # draining its pending storage in a single /poll response
            if rec_batch:
                batch = rec_batch[:]
                del rec_batch[:]
                return batch
            return []
        client.poll = poll

        for meth in ("_ensurePoller", "_consume", "_safeSelector"):
            setattr(client, meth, types.MethodType(getattr(Interactsh, meth), client))
        client.close = lambda: _stop_client_poller(client)
        client._request = lambda *a, **k: None

        srv = InteractshDNSServer.__new__(InteractshDNSServer)
        srv._client = client
        srv.domain = srv._client.dnsDomain()
        srv._seen = set()
        srv._running = True
        srv._initialized = True
        srv._POP_DEADLINE = 1.0
        self.addCleanup(srv.stop)

        poller = _start_test_poller(srv._client)   # real queue/poller, fake already-decoded poll()
        t = time.time() + 2.0
        while not poller._queue and time.time() < t:   # wait for the destructive batch to stage
            time.sleep(0.01)

        self.assertEqual(srv.pop("aaa", "bbb"), dns_full)   # DNS record claimed
        self.assertFalse(srv.pop("aaa", "bbb", deadline=0)) # snapshot after the DNS record is gone
        # the HTTP record with the same full-id is still there for the HTTP consumer
        out = client.httpRequests()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["full-id"], http_full)
        self.assertEqual(out[0]["query-param-names"], ["cafebabe"])

    def test_pop_no_match(self):
        srv = self._collector(["aaa.deadbeef.qqq.corr0000000000000nnc"], deadline=1.0, start_poller=False)
        self.assertIsNone(srv.pop("aaa", "zzz"))

    def test_pop_any(self):
        srv = self._collector(["whatever.corr0000000000000nnc"])
        self.assertEqual(srv.pop(), "whatever.corr0000000000000nnc")
        srv.stop()

    def test_run_is_noop(self):
        srv = self._collector([])
        srv.run()   # must not raise
        srv.stop()

    def test_pop_with_no_poller_installed(self):
        """Backwards-compatible: a server without a running poller resolves pop() via the direct
        (synchronous) poll path."""
        names = ["mmm.cafebabefff.ccc.corr0000000000000nnc"]
        srv = self._collector(names, start_poller=False)
        self.assertEqual(srv.pop("mmm", "ccc", sync=True), names[0])
        srv.stop()

    def test_background_poller_stages_names_instantly(self):
        """With the single background poller running, pop() reads a staged name from its in-memory
        queue with no extra /poll round-trip."""
        names = ["aaa.deadbeef.bbb.corr0000000000000nnc"]
        srv = self._collector(names)   # poller started and its destructive batch staged
        try:
            self.assertTrue(srv._client._poller.isRunning())
            self.assertEqual(_wait_popped(srv, "aaa", "bbb"), names[0])
            self.assertIsNone(srv.pop("aaa", "bbb", deadline=0))   # only one lookup exists (snapshot)
        finally:
            srv.stop()

    def test_background_poller_preserves_foreign_window_names(self):
        """A name for a *different* window survives its own pop() scan - pop(zzz,yyy) must not drain
        the aaa/bbb record, which pop(aaa,bbb) then returns."""
        names = ["aaa.deadbeef.bbb.corr0000000000000nnc"]
        srv = self._collector(names, deadline=1.0)
        try:
            self.assertFalse(srv.pop("zzz", "yyy"))     # wrong window yields nothing (~1s)
            self.assertEqual(srv.pop("aaa", "bbb"), names[0])
            self.assertIsNone(srv.pop("aaa", "bbb", deadline=0))   # only one lookup (snapshot)
        finally:
            srv.stop()

    def test_ensure_poller_starts_only_one_background_thread(self):
        """Concurrent _ensurePoller() callers must converge on a single background poller.

        The create-and-start decision runs under _pollerLock, so two threads racing on an
        unstarted session cannot each build their own poller and destructively poll the same
        interaction session concurrently - precisely what this redesign exists to prevent."""
        from lib.request.interactsh import Interactsh, InteractshPoller, hasCrypto
        if not hasCrypto():
            self.skipTest("requires pycryptodome")
        client = Interactsh.__new__(Interactsh)
        client.registered = True
        client.correlationId = "corr0000000000000nnc"
        client.server = "oast.fun"
        client.secret = "test-secret"
        client._dnsNonce = None
        client._poller = None
        client._pollerLock = threading.Lock()
        client._stopping = False   # set by __init__ in the real client; set it here too
        for meth in ("_ensurePoller", "_consume", "_safeSelector"):
            setattr(client, meth, types.MethodType(getattr(Interactsh, meth), client))
        # stub the remote endpoint and deregister path so the poll loop and client.stop() stay
        # offline while we probe the create/start synchronisation
        client.poll = lambda: []
        client._request = lambda *a, **k: "[]"

        started = []
        orig_start = InteractshPoller.start

        def counting_start(self):
            started.append(self)          # record every poller whose start() is invoked
            orig_start(self)

        client._poller = None
        InteractshPoller.start = counting_start
        try:
            threads = [threading.Thread(target=client._ensurePoller) for _ in range(16)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            InteractshPoller.start = orig_start
        # the single poller was created exactly once and is still running (only one thread
        # ever polled the session)
        self.assertEqual(len(started), 1)                    # start() invoked exactly once
        self.assertEqual(len(set(id(p) for p in started)), 1)   # exactly one InteractshPoller
        self.assertIn(client._poller, started)
        self.assertTrue(client._poller._running)
        # stop the daemon poller before this test returns so its /poll loop (stubbed to [])
        # does not keep looping once per second for the rest of the test process
        client._poller.stop()

    def test_close_stops_poller_and_deregisters(self):
        """close() must remain the canonical complete teardown: after it returns this object owns
        no active polling thread.

        Interactsh.close() predates the background poller and only deregistered, so a running
        poller could keep polling (and race the remote session during deregistration). close()
        now routes through stop()."""
        from lib.request.interactsh import Interactsh, hasCrypto
        if not hasCrypto():
            self.skipTest("requires pycryptodome")
        client = Interactsh.__new__(Interactsh)
        client.registered = True
        client.correlationId = "corr0000000000000nnc"
        client.server = "oast.fun"
        client.secret = "test-secret"
        client._dnsNonce = None
        client._pollerLock = threading.Lock()        # __init__ is bypassed, so set it explicitly
        client._stopping = False                     # __init__ sets it; set it here too
        for meth in ("_ensurePoller", "_consume", "_safeSelector"):
            setattr(client, meth, types.MethodType(getattr(Interactsh, meth), client))
        # stub remote endpoint and deregister path so the poll loop and client.stop() stay offline
        client.poll = lambda: []
        client._request = lambda *a, **k: "[]"

        client._ensurePoller()   # start the single background poller
        self.assertTrue(client._poller.isRunning())

        client.close()           # close() must stop the poller and deregister
        # isRunning() would be False even while the thread still runs when poll() wedged past the
        # join budget; assert the underlying thread is actually gone so the invariant is real.
        self.assertFalse(client._poller._thread.is_alive())   # no active polling thread remains
        self.assertFalse(client._poller.isRunning())
        self.assertFalse(client.registered)
        # cleanup: idempotent - already stopped/deregistered
        self.addCleanup(client.stop)

    def test_consume_does_not_poll_while_stopping(self):
        """_consume() must not do its own destructive /poll during shutdown.

        _consume() used to fall back to self.poll() whenever the poller was not running. Even
        though _ensurePoller() refuses to start a new poller once _stopping is set, pop() can still
        reach that fallback: _stopping is set, the poller is stopped, but _consume() could then
        directly call self.poll() (a destructive /poll) just before stop()'s close(). A direct
        poll during shutdown is exactly the unsynchronised drain that breaks the shared-session
        invariant, so a stopped poller must yield [] - never a direct poll()."""
        from lib.request.interactsh import Interactsh, hasCrypto
        if not hasCrypto():
            self.skipTest("requires pycryptodome")
        client = Interactsh.__new__(Interactsh)   # bypass network __init__
        client.registered = True
        client.correlationId = "corr0000000000000nnc"
        client.server = "oast.fun"
        client.secret = "test-secret"
        client._poller = None
        client._pollerLock = threading.Lock()        # __init__ is bypassed, so set it explicitly
        client._stopping = True                      # simulate an active stop()
        client._dnsNonce = None

        calls = {"poll": 0}

        def spy_poll():
            calls["poll"] += 1
            return []

        client.poll = spy_poll

        for meth in ("_ensurePoller", "_consume", "_safeSelector"):
            setattr(client, meth, types.MethodType(getattr(Interactsh, meth), client))

        # even with no poller at all, a stopped session must not call poll() from _consume
        # (drain_matching on a non-running poller yields [])
        self.assertEqual(client._consume(lambda r: r.get("protocol") == "dns"), [])
        self.assertEqual(client._consume(lambda r: r.get("protocol") == "dns"), [])
        self.assertEqual(calls["poll"], 0)   # sync=False: ensurePoller refused while stopping

        # sync=True must NOT initiate a remote poll once shutdown has begun: the direct-poll path
        # is gated behind _stopping==False, so a stopped session drains the (empty) queue instead
        # - no caller initiates another /poll after stop(), not even this compatibility path.
        self.assertEqual(client._consume(lambda r: r.get("protocol") == "dns", sync=True), [])
        self.assertEqual(calls["poll"], 0)

        # sanity: sync=True still drives poll() on a live (not-stopping) session - this guards
        # against over-closing the safety check to sync itself. _stopping stays False, poller
        # never starts (sync drains directly), so nothing needs cleaning up.
        client._stopping = False
        self.assertEqual(client._consume(lambda r: r.get("protocol") == "dns", sync=True), [])
        self.assertEqual(calls["poll"], 1)

    def test_consume_does_not_second_poll_while_poller_running(self):
        """sync=True must not add a second /poll caller while the background poller is already running.

        The shared-poller invariant is that only ONE code path ever calls the remote /poll endpoint.
        A spurious sync=True during normal operation used to be the footgun: it called self.poll()
        even when a live poller was already draining the session, yielding a second destructive
        /poll. With a running poller sync=True must drain the poller's in-memory queue instead -
        no additional poll() call - and the decision must be serialized under _pollerLock so a
        concurrent _ensurePoller() cannot start a new poller in the gap between the check and the
        (absent) poll()."""
        from lib.request.interactsh import Interactsh, hasCrypto
        if not hasCrypto():
            self.skipTest("requires pycryptodome")
        client = Interactsh.__new__(Interactsh)   # bypass network __init__
        client.registered = True
        client.correlationId = "corr0000000000000nnc"
        client.server = "oast.fun"
        client.secret = "test-secret"
        client._pollerLock = threading.Lock()        # __init__ is bypassed, so set it explicitly
        client._stopping = False
        client._dnsNonce = None
        client._poller = None
        # stub remote + deregister paths so any direct poll() stays offline
        client.poll = lambda: []
        client._request = lambda *a, **k: "[]"
        for meth in ("_ensurePoller", "_consume", "_safeSelector"):
            setattr(client, meth, types.MethodType(getattr(Interactsh, meth), client))
        # start the single background poller, then replace poll with a counting spy AFTER staging.
        # Count only calls made from THIS (foreground) thread: the legitimate background poller
        # thread is permitted to poll(), so thread identity - not a bare call count - isolates the
        # footgun (sync=True issuing a second /poll) from routine background polling.
        main_thread = threading.current_thread()
        foreground_calls = []
        client._ensurePoller()
        self.assertTrue(client._poller.isRunning())

        def spy_poll():
            if threading.current_thread() is main_thread:
                foreground_calls.append(1)
            return []
        client.poll = spy_poll

        # sync=True on a live, poller-running session drains the queue; the running poller is the
        # only code that issues /poll, so the foreground must never call poll() directly.
        self.assertEqual(client._consume(lambda r: r.get("protocol") == "dns", sync=True), [])
        self.assertEqual(client._consume(lambda r: r.get("protocol") == "dns", sync=True), [])
        self.assertEqual(foreground_calls, [])          # sync=True issued no direct /poll
        client.stop()   # join the single (still-running) poll thread



class TestInteractshHTTPRequests(unittest.TestCase):
    """HTTP-based out-of-band retrieval is the collector half of an HTTP-OOB SQLi exfil channel.

    interactsh returns full 'http' protocol records with a verbatim 'raw-request', a
    'protocol' ("http" or "https") and a 'remote-address' - the request line, not a parsed
    path/query. Because an HTTP callback can be blocked (e.g. firewalled query string) and a
    value may contain characters unsafe in a query-string name, the payload is embedded in a
    query-string *parameter name* and httpRequests() decodes and returns the distinct names.

    The request target is split on the *raw* '?'/'&'/first '=' and only each name is percent-
    decoded individually, so encoded delimiter bytes survive (``%26``->'&', ``%3D``->'=',
    ``%25``->'%'); decoding the whole target first would corrupt them."""

    def _client(self, records):
        """Fake client carrying the records in poll(), wired to the real poller-aware consume path.

        Records are returned once (destructive, like a draining interactsh endpoint) and the
        poller is started so httpRequests() exercises the normal registered-poller path; teardown
        cannot reach the network."""
        from lib.request.interactsh import Interactsh
        client = Interactsh.__new__(Interactsh)   # bypass network __init__
        client.registered = True
        client.correlationId = "corr0000000000000nnc"
        client.server = "oast.fun"
        client.secret = "test-secret"
        client._pollerLock = threading.Lock()   # __init__ is bypassed, so set it explicitly
        client._stopping = False               # __init__ sets it; set it here too

        rec_batch = list(records)

        def poll():
            # return the whole batch once, then nothing - mirrors an interactsh endpoint
            # draining its pending storage in a single /poll response
            if rec_batch:
                batch = rec_batch[:]
                del rec_batch[:]
                return batch
            return []
        client.poll = poll

        for meth in ("_ensurePoller", "_consume", "_safeSelector"):
            setattr(client, meth, types.MethodType(getattr(Interactsh, meth), client))

        client.close = lambda: _stop_client_poller(client)
        client._request = lambda *a, **k: None

        poller = _start_test_poller(client)
        t = time.time() + 2.0
        while not poller._queue and time.time() < t:
            time.sleep(0.01)
        # client.stop() (registered as cleanup) stops the single background poller then
        # deregisters, so the poll thread never outlives this test and never reaches the network
        self.addCleanup(client.stop)
        return client

    def test_extracts_query_param_names_from_raw_request(self):
        records = [{"protocol": "http", "full-id": "a.b.c", "raw-request": "GET /?deadbeef=cafebabe HTTP/1.1", "remote-address": "1.2.3.4"}]
        client = self._client(records)
        out = client.httpRequests()
        self.assertEqual(len(out), 1)
        # only the query-string *name* is the attacker-controlled exfil slot; the value rides on it
        self.assertEqual(out[0]["query-param-names"], ["deadbeef"])
        self.assertEqual(out[0]["client"], "1.2.3.4")
        self.assertEqual(out[0]["request"], "GET /?deadbeef=cafebabe HTTP/1.1")

    def test_decodes_each_name_individually(self):
        """Encoded delimiter bytes must survive split: each name is decoded on its own."""
        records = [
            {"protocol": "https", "full-id": "a", "raw-request": "GET /?aa%26bb=1 HTTP/1.1"},   # %26 -> '&'
            {"protocol": "https", "full-id": "b", "raw-request": "GET /?cc%3Ddd=1 HTTP/1.1"},   # %3D -> '='
            {"protocol": "https", "full-id": "c", "raw-request": "GET /?ee%25ff=1 HTTP/1.1"},   # %25 -> '%'
        ]
        client = self._client(records)
        out = client.httpRequests()
        self.assertEqual([r["query-param-names"] for r in out], [["aa&bb"], ["cc=dd"], ["ee%ff"]])

    def test_skips_non_http_records(self):
        records = [{"protocol": "dns", "full-id": "x.y"}]
        client = self._client(records)
        self.assertEqual(client.httpRequests(), [])

    def test_distinct_names_are_not_duplicated(self):
        records = [{"protocol": "http", "full-id": "a", "raw-request": "GET /?deadbeef=1 HTTP/1.1"},
                   {"protocol": "http", "full-id": "b", "raw-request": "GET /?cafebabe=2 HTTP/1.1"}]
        client = self._client(records)
        out = client.httpRequests()
        names = [name for r in out for name in r["query-param-names"]]
        self.assertEqual(set(names), {"deadbeef", "cafebabe"})

    def test_empty_poll_returns_empty(self):
        client = self._client([])
        self.assertEqual(client.httpRequests(), [])

    def test_selector_exception_is_absorbed(self):
        """A selector that raises must be caught (not propagated out of httpRequests/_consume)"""
        records = [{"protocol": "http", "full-id": "a", "raw-request": "GET /?x=1 HTTP/1.1"}]
        client = self._client(records)

        def boom(record):
            raise ValueError("boom")

        self.assertEqual(client._consume(boom, deadline=None), [])

    def test_multiple_http_same_host_are_not_dropped(self):
        """The reviewer's core case: several HTTP requests hitting the same interactsh host - i.e.
        sharing 'full-id' - must all survive the poller's dedup. Dedup is by the interaction
        itself (protocol+full-id+id/timestamp+raw-request), never by the shared host."""
        records = [
            {"protocol": "dns", "full-id": "abc..."},
            {"protocol": "http", "full-id": "abc...", "raw-request": "GET /?deadbeef=1 HTTP/1.1"},
            {"protocol": "http", "full-id": "abc...", "raw-request": "GET /?cafebabe=1 HTTP/1.1"},
        ]
        client = self._client(records)
        out = client.httpRequests()
        names = [name for r in out for name in r["query-param-names"]]
        self.assertEqual(set(names), {"deadbeef", "cafebabe"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
