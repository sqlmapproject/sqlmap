#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Native, dependency-free NTLM-over-HTTP authentication (MS-NLMP / MS-NTHT), replacing the ancient
# and unmaintained 'python-ntlm' third-party library. Pure standard library + the in-tree pyDes for
# the DES core (hashlib's MD4 is unavailable under OpenSSL 3's unloaded legacy provider, so MD4 is
# implemented here per RFC 1320). Python 2.7 / 3.x. Crypto validated against the [MS-NLMP] test vectors.

import base64
import binascii
import os
import re
import socket
import ssl
import struct

from lib.core.convert import getBytes
from lib.core.convert import getText
from thirdparty.pydes.pyDes import des
from thirdparty.pydes.pyDes import ECB
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import urllib as _urllib

# ---------- MD4 (RFC 1320) ----------
def _md4(data):
    data = bytearray(data)
    n = len(data)
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data += struct.pack("<Q", (n * 8) & 0xffffffffffffffff)

    a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    M = 0xffffffff
    rot = lambda x, s: ((x << s) | (x >> (32 - s))) & M

    for off in range(0, len(data), 64):
        X = struct.unpack("<16I", bytes(data[off:off + 64]))
        A, B, C, D = a, b, c, d
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & y) | (x & z) | (y & z)
        H = lambda x, y, z: x ^ y ^ z

        for k in (0, 4, 8, 12):
            A = rot((A + F(B, C, D) + X[k]) & M, 3)
            D = rot((D + F(A, B, C) + X[k + 1]) & M, 7)
            C = rot((C + F(D, A, B) + X[k + 2]) & M, 11)
            B = rot((B + F(C, D, A) + X[k + 3]) & M, 19)
        for k in (0, 1, 2, 3):
            A = rot((A + G(B, C, D) + X[k] + 0x5a827999) & M, 3)
            D = rot((D + G(A, B, C) + X[k + 4] + 0x5a827999) & M, 5)
            C = rot((C + G(D, A, B) + X[k + 8] + 0x5a827999) & M, 9)
            B = rot((B + G(C, D, A) + X[k + 12] + 0x5a827999) & M, 13)
        for k in (0, 2, 1, 3):
            A = rot((A + H(B, C, D) + X[k] + 0x6ed9eba1) & M, 3)
            D = rot((D + H(A, B, C) + X[k + 8] + 0x6ed9eba1) & M, 9)
            C = rot((C + H(D, A, B) + X[k + 4] + 0x6ed9eba1) & M, 11)
            B = rot((B + H(C, D, A) + X[k + 12] + 0x6ed9eba1) & M, 15)

        a, b, c, d = (a + A) & M, (b + B) & M, (c + C) & M, (d + D) & M

    return struct.pack("<4I", a, b, c, d)

# ---------- DES core (in-tree pyDes) with the NTLM 7->8 byte parity key expansion ----------
def _str_to_key(chunk):
    s = bytearray(chunk)
    k = [s[0] >> 1,
         ((s[0] & 0x01) << 6) | (s[1] >> 2),
         ((s[1] & 0x03) << 5) | (s[2] >> 3),
         ((s[2] & 0x07) << 4) | (s[3] >> 4),
         ((s[3] & 0x0f) << 3) | (s[4] >> 5),
         ((s[4] & 0x1f) << 2) | (s[5] >> 6),
         ((s[5] & 0x3f) << 1) | (s[6] >> 7),
         s[6] & 0x7f]
    return bytes(bytearray((_ << 1) & 0xff for _ in k))

def _des(key7, block8):
    return des(_str_to_key(key7), ECB).encrypt(block8)

# ---------- negotiate flags ----------
NTLM_NegotiateUnicode = 0x00000001
NTLM_NegotiateOEM = 0x00000002
NTLM_RequestTarget = 0x00000004
NTLM_NegotiateNTLM = 0x00000200
NTLM_NegotiateOemDomainSupplied = 0x00001000
NTLM_NegotiateOemWorkstationSupplied = 0x00002000
NTLM_NegotiateAlwaysSign = 0x00008000
NTLM_NegotiateExtendedSecurity = 0x00080000
NTLM_NegotiateTargetInfo = 0x00800000
NTLM_NegotiateVersion = 0x02000000
NTLM_Negotiate128 = 0x20000000
NTLM_Negotiate56 = 0x80000000
NTLM_MsvAvTimestamp = 7

NTLM_TYPE1_FLAGS = (NTLM_NegotiateUnicode | NTLM_NegotiateOEM | NTLM_RequestTarget | NTLM_NegotiateNTLM |
                    NTLM_NegotiateOemDomainSupplied | NTLM_NegotiateOemWorkstationSupplied |
                    NTLM_NegotiateAlwaysSign | NTLM_NegotiateExtendedSecurity | NTLM_NegotiateVersion |
                    NTLM_Negotiate128 | NTLM_Negotiate56)
NTLM_TYPE2_FLAGS = (NTLM_NegotiateUnicode | NTLM_RequestTarget | NTLM_NegotiateNTLM |
                    NTLM_NegotiateAlwaysSign | NTLM_NegotiateExtendedSecurity | NTLM_NegotiateTargetInfo |
                    NTLM_NegotiateVersion | NTLM_Negotiate128 | NTLM_Negotiate56)

_HASH_RE = re.compile(r"\A[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\Z")

# ---------- password hashes / challenge responses ----------
def create_LM_hashed_password_v1(password):
    if _HASH_RE.match(password):
        return binascii.unhexlify(password.split(':')[0])
    pw = (getBytes(password.upper()) + b"\0" * 14)[:14]
    return _des(pw[0:7], b"KGS!@#$%") + _des(pw[7:14], b"KGS!@#$%")

def create_NT_hashed_password_v1(password, user=None, domain=None):
    if _HASH_RE.match(password):
        return binascii.unhexlify(password.split(':')[1])
    return _md4(password.encode("utf-16-le"))

def calc_resp(password_hash, server_challenge):
    ph = password_hash + b"\0" * (21 - len(password_hash))
    return _des(ph[0:7], server_challenge) + _des(ph[7:14], server_challenge) + _des(ph[14:21], server_challenge)

def ntlm2sr_calc_resp(nt_hash, server_challenge, client_challenge):
    import hashlib
    lm_response = client_challenge + b"\0" * 16
    session = hashlib.md5(server_challenge + client_challenge).digest()
    nt_response = calc_resp(nt_hash, session[0:8])
    return (nt_response, lm_response)

# ---------- messages ----------
def create_NTLM_NEGOTIATE_MESSAGE(user, type1_flags=NTLM_TYPE1_FLAGS):
    workstation = getBytes(socket.gethostname().upper())
    domain = getBytes(user.split('\\', 1)[0].upper())
    body = 40
    msg = b"NTLMSSP\0" + struct.pack("<I", 1) + struct.pack("<I", type1_flags)
    msg += struct.pack("<HHI", len(domain), len(domain), body)
    msg += struct.pack("<HHI", len(workstation), len(workstation), body + len(domain))
    msg += struct.pack("<BBHBBBB", 5, 1, 2600, 0, 0, 0, 15)      # advertised OS version
    msg += workstation + domain
    return getText(base64.b64encode(msg))

def parse_NTLM_CHALLENGE_MESSAGE(msg2):
    msg = base64.b64decode(msg2)
    negotiate_flags = struct.unpack("<I", msg[20:24])[0]
    server_challenge = msg[24:32]
    return (server_challenge, negotiate_flags)

def create_NTLM_AUTHENTICATE_MESSAGE(nonce, user, domain, password, negotiate_flags):
    is_unicode = negotiate_flags & NTLM_NegotiateUnicode
    is_extended = negotiate_flags & NTLM_NegotiateExtendedSecurity

    workstation = socket.gethostname().upper()
    domain = domain.upper()
    if is_unicode:
        workstation = workstation.encode("utf-16-le")
        domain = domain.encode("utf-16-le")
        username = user.encode("utf-16-le")
    else:
        workstation = getBytes(workstation)
        domain = getBytes(domain)
        username = getBytes(user)

    lm_response = calc_resp(create_LM_hashed_password_v1(password), nonce)
    nt_response = calc_resp(create_NT_hashed_password_v1(password), nonce)
    if is_extended:
        nt_hash = create_NT_hashed_password_v1(password)
        client_challenge = os.urandom(8)
        nt_response, lm_response = ntlm2sr_calc_resp(nt_hash, nonce, client_challenge)

    body = 72
    payload = domain + username + workstation + lm_response + nt_response
    fields = b"NTLMSSP\0" + struct.pack("<I", 3)
    fields += struct.pack("<HHI", len(lm_response), len(lm_response), body + len(domain) + len(username) + len(workstation))
    fields += struct.pack("<HHI", len(nt_response), len(nt_response), body + len(domain) + len(username) + len(workstation) + len(lm_response))
    fields += struct.pack("<HHI", len(domain), len(domain), body)
    fields += struct.pack("<HHI", len(username), len(username), body + len(domain))
    fields += struct.pack("<HHI", len(workstation), len(workstation), body + len(domain) + len(username))
    fields += struct.pack("<HHI", 0, 0, body + len(payload))     # empty EncryptedRandomSessionKey
    fields += struct.pack("<I", NTLM_TYPE2_FLAGS)
    fields += struct.pack("<BBHBBBB", 5, 1, 2600, 0, 0, 0, 15)
    return getText(base64.b64encode(fields + payload))

# ---------- urllib handler ----------
class _AbstractNtlmAuthHandler(object):
    def __init__(self, password_mgr=None):
        self.passwd = password_mgr or _urllib.request.HTTPPasswordMgr()
        self.add_password = self.passwd.add_password

    def _authenticate(self, auth_header_field, req, headers):
        auth_header_value = headers.get(auth_header_field, None)
        if auth_header_value is not None and 'ntlm' in auth_header_value.lower():
            return self._retry_ntlm(req, auth_header_field)

    def _retry_ntlm(self, req, auth_header_field):
        user, pw = self.passwd.find_user_password(None, req.get_full_url())
        if pw is None:
            return None

        parts = user.split('\\', 1)
        if len(parts) == 1:
            username, domain = parts[0], ''
            type1_flags = NTLM_TYPE1_FLAGS & ~NTLM_NegotiateOemDomainSupplied
        else:
            domain, username = parts[0].upper(), parts[1]
            type1_flags = NTLM_TYPE1_FLAGS

        # NTLM authenticates the CONNECTION, not the request, so the whole handshake rides one socket
        headers = dict(req.headers)
        headers.update(req.unredirected_hdrs)
        negotiate = 'NTLM %s' % create_NTLM_NEGOTIATE_MESSAGE(user, type1_flags)
        if req.headers.get(self.auth_header, None) == negotiate:
            return None
        headers[self.auth_header] = negotiate

        host = req.host if hasattr(req, "host") else req.get_host()
        if not host:
            raise _urllib.error.URLError("no host given")
        if req.get_full_url().startswith("https://"):
            conn = _http_client.HTTPSConnection(host, context=ssl._create_unverified_context())
        else:
            conn = _http_client.HTTPConnection(host)

        selector = req.selector if hasattr(req, "selector") else req.get_selector()
        method = req.get_method()

        headers["Connection"] = "Keep-Alive"
        headers = dict((name.title(), value) for name, value in headers.items())
        conn.request(method, selector, req.data, headers)
        resp = conn.getresponse()
        resp.read()                                              # drain the challenge body, keep the socket
        if resp.getheader("set-cookie"):                         # some apps track auth state in a cookie
            headers["Cookie"] = resp.getheader("set-cookie")
        auth_header_value = resp.getheader(auth_header_field, None)

        match = re.match(r"(NTLM [A-Za-z0-9+\-/=]+)", auth_header_value or "")
        if not match:
            return None
        server_challenge, negotiate_flags = parse_NTLM_CHALLENGE_MESSAGE(match.group(1)[5:])

        headers[self.auth_header] = 'NTLM %s' % create_NTLM_AUTHENTICATE_MESSAGE(server_challenge, username, domain, pw, negotiate_flags)
        headers["Connection"] = "Close"
        headers = dict((name.title(), value) for name, value in headers.items())
        try:
            conn.request(method, selector, req.data, headers)
            resp = conn.getresponse()
            if not hasattr(resp, "readline"):        # Python 2 httplib responses lack it; addinfourl copies it
                resp.readline = lambda *args, **kwargs: b""
            infourl = _urllib.response.addinfourl(resp, resp.msg, req.get_full_url())
            infourl.code = resp.status
            infourl.msg = resp.reason
            return infourl
        except socket.error as ex:
            raise _urllib.error.URLError(ex)

class HTTPNtlmAuthHandler(_AbstractNtlmAuthHandler, _urllib.request.BaseHandler):
    auth_header = "Authorization"

    def http_error_401(self, req, fp, code, msg, headers):
        fp.close()
        return self._authenticate("www-authenticate", req, headers)

class ProxyNtlmAuthHandler(_AbstractNtlmAuthHandler, _urllib.request.BaseHandler):
    auth_header = "Proxy-authorization"

    def http_error_407(self, req, fp, code, msg, headers):
        fp.close()
        return self._authenticate("proxy-authenticate", req, headers)
