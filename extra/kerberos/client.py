#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Dependency-free Kerberos 5 client (RFC 4120) built on the in-tree DER codec and RFC 3961/3962
# crypto. Implements the AS exchange (password -> TGT) with PA-ENC-TIMESTAMP pre-authentication;
# the TGS exchange and AP-REQ follow. Talks to the KDC over TCP (4-byte length framing).
# Python 2.7 / 3.x.

import calendar
import os
import socket
import struct
import threading
import time

from extra.kerberos import der
from extra.kerberos import spnego
from extra.kerberos.crypto import ENCTYPES

GSS_CHECKSUM_TYPE = 0x8003                                  # RFC 4121 section 4.1.1 authenticator checksum
GSS_CHECKSUM_FLAGS = 0                                      # no GSS context flags requested (no mutual/deleg)
TICKET_LIFETIME_SECONDS = 10 * 3600                        # requested 'till' offset (KDC clamps to its max)

# message types
AS_REQ, AS_REP, TGS_REQ, TGS_REP, AP_REQ, KRB_ERROR = 10, 11, 12, 13, 14, 30

# principal name types
NT_PRINCIPAL, NT_SRV_INST = 1, 2

# PA-DATA types
PA_TGS_REQ, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2 = 1, 2, 19

# KDC error code that carries the PA-ETYPE-INFO2 hint (etype/salt/iteration count) for pre-auth
KDC_ERR_PREAUTH_REQUIRED = 25

# key usages (RFC 4120 section 7.5.1)
USAGE_AS_REQ_PA_ENC_TIMESTAMP = 1
USAGE_AS_REP_ENCPART = 3
USAGE_TGS_REQ_AUTH_CKSUM = 6
USAGE_TGS_REQ_AUTH = 7
USAGE_TGS_REP_ENCPART = 8
USAGE_AP_REQ_AUTH = 11

PVNO = 5
DEFAULT_ETYPES = (18, 17, 23)                               # aes256-cts, aes128-cts, rc4-hmac (best first)
KDC_TIMEOUT = 10                                            # seconds for the KDC TCP exchange
MAX_KDC_RESPONSE = 8 * 1024 * 1024                          # cap on a KDC reply (guards a hostile length prefix)
KERBEROS_TIME_FORMAT = "%Y%m%d%H%M%SZ"                      # RFC 4120 KerberosTime (always UTC)

# Bounds on the string-to-key work factor a KDC may ask for. The PA-ETYPE-INFO2 hint carrying it
# arrives on an *unauthenticated* KRB-ERROR, and the field is a full 32 bits, so an absurd value would
# either weaken the derived key against offline guessing or burn hours of CPU (RFC 3962 warns about
# both and recommends configurable bounds). A count of 0 nominally means 2**32, which we cannot honour.
MIN_PBKDF2_ITERATIONS = 4096                                # the RFC 3962 default; nothing legitimate is lower
MAX_PBKDF2_ITERATIONS = 1000000

def _enctype(etype):
    if etype not in ENCTYPES:
        raise KerberosError(-1, "unsupported encryption type %d (only AES-CTS-HMAC-SHA1 is implemented)" % etype)
    return ENCTYPES[etype]

class KerberosError(Exception):
    def __init__(self, code, text=None):
        Exception.__init__(self, "KDC error %d%s" % (code, ": %s" % text if text else ""))
        self.code = code

# ---- EXPLICIT-tag unwrap helpers ------------------------------------------------------------------
# Kerberos uses EXPLICIT tagging: an [n] field's content is a complete inner TLV, so it must be
# peeled before the value can be read. _fields() maps a SEQUENCE's [n] children to that inner TLV.
def _fields(sequenceContent):
    out = {}
    for tag, inner in der.children(sequenceContent):
        if 0xA0 <= tag <= 0xBE:                             # context-specific, constructed [0]..[30]
            out[tag - 0xA0] = inner
    return out

def _expInteger(field):
    return der.decodeInteger(der.peel(field)[1])

def _expString(field):
    return der.decodeGeneralString(der.peel(field)[1])

def _expOctet(field):
    return bytes(der.peel(field)[1])

def _expFields(field):
    """For an [n] field whose inner TLV is a SEQUENCE, return that SEQUENCE's field map."""

    return _fields(der.peel(field)[1])

# ---- message building -----------------------------------------------------------------------------
def _nonce():
    return struct.unpack(">I", os.urandom(4))[0] & 0x7fffffff

def _kerberosTime(offsetSeconds=0):
    return time.strftime(KERBEROS_TIME_FORMAT, time.gmtime(time.time() + offsetSeconds))

_timestampLock = threading.Lock()
_lastMicros = -1

def _timestamp():
    """(KerberosTime, microseconds) taken from a single clock reading and unique within the process.

    An acceptor's replay cache rejects a repeated (ctime, cusec) for the same principal and service,
    and a threaded scan mints an authenticator per request, so the pair must never repeat; a strictly
    increasing microsecond counter also keeps cusec inside its INTEGER (0..999999) range by construction.
    """

    global _lastMicros

    with _timestampLock:
        micros = max(int(time.time() * 1000000), _lastMicros + 1)
        _lastMicros = micros
    return time.strftime(KERBEROS_TIME_FORMAT, time.gmtime(micros // 1000000)), micros % 1000000

def _expTime(field):
    """An [n]-wrapped KerberosTime as epoch seconds (None when absent or unparsable, so an unusual
    time format degrades ticket-expiry tracking rather than failing the exchange)."""

    try:
        return calendar.timegm(time.strptime(der.decodeGeneralString(der.peel(field)[1]), KERBEROS_TIME_FORMAT))
    except ValueError:
        return None

def _principalName(nameType, components):
    return der.sequence(
        der.tagged(0, der.integer(nameType)),
        der.tagged(1, der.sequenceOf([der.generalString(_) for _ in components])),
    )

def _encryptedData(etype, cipher, kvno=None):
    parts = [der.tagged(0, der.integer(etype))]
    if kvno is not None:
        parts.append(der.tagged(1, der.integer(kvno)))
    parts.append(der.tagged(2, der.octetString(cipher)))
    return der.sequence(*parts)

# ---- KDC transport (RFC 4120 section 7.2.2: 4-byte length-prefixed over TCP) ----------------------
def _recvExactly(sock, count):
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise KerberosError(-1, "connection closed by KDC")
        buf += chunk
    return buf

def _sendReceive(host, port, request):
    sock = socket.create_connection((host, port), timeout=KDC_TIMEOUT)
    try:
        sock.sendall(struct.pack(">I", len(request)) + request)
        length = struct.unpack(">I", _recvExactly(sock, 4))[0]
        if length > MAX_KDC_RESPONSE:
            raise KerberosError(-1, "KDC reply length %d exceeds the sane maximum" % length)
        return _recvExactly(sock, length)
    finally:
        sock.close()

def _raiseIfError(message):
    tag, content, _ = der.peel(message)
    if tag == der.applicationTag(KRB_ERROR):
        fields = _fields(der.peel(content)[1])
        raise KerberosError(_expInteger(fields[6]) if 6 in fields else -1,
                            _expString(fields[11]) if 11 in fields else None)
    return tag, content

def _etypeHints(methodData):
    """Parse a METHOD-DATA TLV (SEQUENCE OF PA-DATA) into PA-ETYPE-INFO2 hints as
    {etype: (salt, iterations)}, telling us which etype/salt/s2kparams the KDC expects for the
    long-term key. The first entry for an etype wins; a malformed hint yields none (so the caller
    falls back to its defaults) rather than raising."""

    hints = {}
    try:
        for _, paData in der.children(der.peel(methodData)[1]):
            pa = _fields(paData)
            if 1 in pa and 2 in pa and _expInteger(pa[1]) == PA_ETYPE_INFO2:
                info = der.peel(pa[2])[1]                   # padata-value OCTET STRING -> ETYPE-INFO2 (SEQ OF entry)
                for _, entry in der.children(der.peel(info)[1]):
                    fields = _fields(entry)
                    salt = _expOctet(fields[1]) if 1 in fields else None   # opaque octets for string2key (RFC 3961), not UTF-8
                    iterations = None
                    if 2 in fields:
                        raw = bytes(der.peel(fields[2])[1]) # s2kparams: 4-byte BE iteration count for AES
                        iterations = struct.unpack(">I", raw)[0] if len(raw) == 4 else None
                    hints.setdefault(_expInteger(fields[0]), (salt, iterations))
    except (KeyError, IndexError, ValueError, struct.error):
        hints.clear()                                       # malformed hint -> fall back to the default etype/salt
    return hints

def _preauthHints(errorFields):
    """The etype hints carried by a KDC_ERR_PREAUTH_REQUIRED error's e-data (best effort)."""

    if 12 not in errorFields:                              # no e-data
        return {}
    try:
        return _etypeHints(der.peel(errorFields[12])[1])   # e-data OCTET STRING -> METHOD-DATA
    except (KeyError, IndexError, ValueError, struct.error):
        return {}

def _validatedIterations(iterations):
    """Refuse a string-to-key work factor outside local policy. The hint is unauthenticated, so a
    spoofed count could either cheapen an offline attack on the PA-ENC-TIMESTAMP we are about to send
    or stall the scan for hours; failing loudly beats doing either silently."""

    if iterations is not None and not MIN_PBKDF2_ITERATIONS <= iterations <= MAX_PBKDF2_ITERATIONS:
        raise KerberosError(-1, "KDC advertised an out-of-policy string-to-key iteration count (%d)" % iterations)
    return iterations

def _hintFor(hints, etype, salt, chosenSalt):
    """Apply the hint for 'etype': its salt (unless the caller pinned one) and its work factor."""

    advertisedSalt, iterations = hints.get(etype, (None, None))
    if salt is None and advertisedSalt is not None:
        chosenSalt = advertisedSalt
    return chosenSalt, _validatedIterations(iterations)

def _replyEtype(response):
    """Return the etype of a KDC-REP's enc-part (which etype the KDC used for the client's key)."""

    try:
        rep = _fields(der.peel(der.peel(response)[1])[1])
        return _expInteger(_expFields(rep[6])[0])
    except (KeyError, IndexError, ValueError, struct.error):
        raise KerberosError(-1, "malformed KDC reply")

def _parseRep(response, key, usage, expectedNonce, expectedType):
    """Parse an AS-REP / TGS-REP: decrypt its enc-part with 'key' under 'usage', returning the
    opaque ticket and the freshly issued session key. The two replies are structurally identical.
    The reply's application tag MUST match the expected message type, and the nonce carried in the
    (integrity-protected) enc-part MUST equal the request nonce (RFC 4120)."""

    try:                                                   # any structural defect in a hostile/truncated reply -> KerberosError
        tag, repContent = _raiseIfError(response)
        if tag != der.applicationTag(expectedType):
            raise KerberosError(-1, "unexpected reply message type (tag 0x%02x)" % tag)
        rep = _fields(der.peel(repContent)[1])
        encData = _expFields(rep[6])                        # enc-part (EncryptedData)
        repEtype = _expInteger(encData[0])
        try:
            encRepPart = _enctype(repEtype).decrypt(key, usage, _expOctet(encData[2]))
        except ValueError:                                 # HMAC mismatch -> we hold the wrong long-term key
            raise KerberosError(-1, "reply decryption failed (wrong password or salt)")

        # Enc*RepPart = [APPLICATION 25/26] EncKDCRepPart ; key is field [0], nonce is field [2]
        encKdcRep = _fields(der.peel(der.peel(encRepPart)[1])[1])
        if _expInteger(encKdcRep[2]) != expectedNonce:
            raise KerberosError(-1, "reply nonce does not match the request (possible replay)")
        keyFields = _expFields(encKdcRep[0])

        return {
            "ticket": bytes(rep[5]),
            "sessionKey": _expOctet(keyFields[1]),
            "sessionKeyType": _expInteger(keyFields[0]),
            "etype": repEtype,
            "crealm": _expString(rep[3]),
            # EncKDCRepPart endtime [7]; a scan can outlive the ticket, so the caller can re-fetch
            "endtime": _expTime(encKdcRep[7]) if 7 in encKdcRep else None,
        }
    except (KeyError, IndexError, ValueError, struct.error):
        raise KerberosError(-1, "malformed KDC reply")

def _reqBody(realm, snameType, snameComponents, etypes, nonce, cnameComponents=None):
    parts = [der.tagged(0, der.bitString(b"\x00\x00\x00\x00"))]                      # kdc-options
    if cnameComponents is not None:
        parts.append(der.tagged(1, _principalName(NT_PRINCIPAL, cnameComponents)))  # cname (AS only)
    parts.append(der.tagged(2, der.generalString(realm)))                           # realm
    parts.append(der.tagged(3, _principalName(snameType, snameComponents)))         # sname
    parts.append(der.tagged(5, der.generalizedTime(_kerberosTime(offsetSeconds=TICKET_LIFETIME_SECONDS))))  # till
    parts.append(der.tagged(7, der.integer(nonce)))                                 # nonce
    parts.append(der.tagged(8, der.sequenceOf([der.integer(_) for _ in etypes])))   # etype
    return der.sequence(*parts)

def _authenticator(crealm, cnameComponents, cksum=None, seqNumber=None):
    ctime, cusec = _timestamp()                             # both from one clock reading, never repeating
    parts = [
        der.tagged(0, der.integer(PVNO)),
        der.tagged(1, der.generalString(crealm)),
        der.tagged(2, _principalName(NT_PRINCIPAL, cnameComponents)),
    ]
    if cksum is not None:
        parts.append(der.tagged(3, der.sequence(der.tagged(0, der.integer(cksum[0])),
                                                 der.tagged(1, der.octetString(cksum[1])))))
    parts.append(der.tagged(4, der.integer(cusec)))
    parts.append(der.tagged(5, der.generalizedTime(ctime)))
    if seqNumber is not None:                               # [7] seq-number, expected of a GSS AP-REQ
        parts.append(der.tagged(7, der.integer(seqNumber)))
    return der.application(2, der.sequence(*parts))

def _apReq(ticket, encAuthenticator, etype, apOptions=b"\x00\x00\x00\x00"):
    return der.application(AP_REQ, der.sequence(
        der.tagged(0, der.integer(PVNO)),
        der.tagged(1, der.integer(AP_REQ)),
        der.tagged(2, der.bitString(apOptions)),
        der.tagged(3, ticket),                              # raw Ticket TLV (already [APPLICATION 1])
        der.tagged(4, _encryptedData(etype, encAuthenticator)),
    ))

# ---- AS exchange (password -> TGT) ----------------------------------------------------------------
def _asReq(realm, username, etypes, nonce, padata=None):
    reqBody = _reqBody(realm, NT_SRV_INST, ["krbtgt", realm], etypes, nonce, cnameComponents=[username])
    parts = [der.tagged(1, der.integer(PVNO)), der.tagged(2, der.integer(AS_REQ))]
    if padata is not None:
        parts.append(der.tagged(3, der.sequenceOf([padata])))
    parts.append(der.tagged(4, reqBody))
    return der.application(AS_REQ, der.sequence(*parts))

def _selectEtype(etypes, hints):
    """
    The etype getTGT commits to after a preauth-required hint: OUR first offered etype that is also
    KDC-hinted and supported, falling back to our top preference. The unauthenticated hint can only
    reorder WITHIN what we offered - it can never pull us onto an etype we did not offer (anti-downgrade).
    """

    return next((_ for _ in etypes if _ in hints and _ in ENCTYPES), etypes[0])

def getTGT(realm, username, password, kdcHost, kdcPort=88, etypes=DEFAULT_ETYPES, salt=None):
    """Run the AS exchange and return the TGT and its session key.

    Follows the standard two-step flow: an initial request without pre-auth learns the KDC's expected
    etype/salt/iteration-count from PA-ETYPE-INFO2 (so non-default salts and AES-128-only principals
    work), then a PA-ENC-TIMESTAMP-authenticated request obtains the ticket. Returns
    {'ticket': <raw Ticket TLV>, 'sessionKey': bytes, 'sessionKeyType': int, 'crealm': str,
    'endtime': epoch seconds}. 'realm' is used exactly as given (RFC 4120 realms are case-sensitive).
    """

    chosenSalt = salt if salt is not None else realm + username

    # 1) probe without pre-auth to discover the etype/salt/iterations (or get the TGT outright)
    nonce = _nonce()
    response = _sendReceive(kdcHost, kdcPort, _asReq(realm, username, etypes, nonce))
    tag = der.peel(response)[0]

    if tag == der.applicationTag(AS_REP):                  # KDC issued the ticket without pre-auth
        etype = _replyEtype(response)                      # derive the key for the etype the KDC actually used
        rep = _fields(der.peel(der.peel(response)[1])[1])
        # the reply's own padata can still carry the salt/iterations of a non-default principal
        chosenSalt, iterations = _hintFor(_etypeHints(rep[2]) if 2 in rep else {}, etype, salt, chosenSalt)
        clientKey = _enctype(etype).string2key(password, chosenSalt, iterations)
        return _parseRep(response, clientKey, USAGE_AS_REP_ENCPART, nonce, AS_REP)

    etype, iterations = etypes[0], None
    if tag == der.applicationTag(KRB_ERROR):
        errorFields = _fields(der.peel(der.peel(response)[1])[1])
        code = _expInteger(errorFields[6]) if 6 in errorFields else -1
        if code != KDC_ERR_PREAUTH_REQUIRED:
            raise KerberosError(code, _expString(errorFields[11]) if 11 in errorFields else None)
        # the hint is unauthenticated, so it may only choose among the etypes we actually offered, and
        # in *our* order of preference rather than the KDC's (otherwise it could force a downgrade)
        hints = _preauthHints(errorFields)
        etype = _selectEtype(etypes, hints)
        chosenSalt, iterations = _hintFor(hints, etype, salt, chosenSalt)

    enc = _enctype(etype)
    clientKey = enc.string2key(password, chosenSalt, iterations)

    # 2) authenticated request with PA-ENC-TIMESTAMP under the discovered etype/salt
    patime, pausec = _timestamp()
    paTsEnc = der.sequence(der.tagged(0, der.generalizedTime(patime)), der.tagged(1, der.integer(pausec)))
    cipher = enc.encrypt(clientKey, USAGE_AS_REQ_PA_ENC_TIMESTAMP, paTsEnc)
    paData = der.sequence(
        der.tagged(1, der.integer(PA_ENC_TIMESTAMP)),
        der.tagged(2, der.octetString(_encryptedData(etype, cipher))),
    )
    nonce = _nonce()
    response = _sendReceive(kdcHost, kdcPort, _asReq(realm, username, etypes, nonce, padata=paData))
    return _parseRep(response, clientKey, USAGE_AS_REP_ENCPART, nonce, AS_REP)

# ---- TGS exchange (TGT -> service ticket) ---------------------------------------------------------
def getServiceTicket(tgt, realm, username, serviceComponents, kdcHost, kdcPort=88, etypes=DEFAULT_ETYPES):
    """Present the TGT in a PA-TGS-REQ AP-REQ to obtain a ticket for the named service.

    Returns the same shape as getTGT (the 'ticket' is now the service ticket). Cross-realm referrals
    are not followed, so 'serviceComponents' must name a service inside 'realm'.
    """

    enc = _enctype(tgt["sessionKeyType"])
    nonce = _nonce()
    reqBody = _reqBody(realm, NT_SRV_INST, serviceComponents, etypes, nonce)

    cksum = (enc.cksumtype, enc.checksum(tgt["sessionKey"], USAGE_TGS_REQ_AUTH_CKSUM, reqBody))
    authenticator = _authenticator(realm, [username], cksum=cksum)
    encAuth = enc.encrypt(tgt["sessionKey"], USAGE_TGS_REQ_AUTH, authenticator)
    apReq = _apReq(tgt["ticket"], encAuth, tgt["sessionKeyType"])

    paTgs = der.sequence(der.tagged(1, der.integer(PA_TGS_REQ)), der.tagged(2, der.octetString(apReq)))
    tgsReq = der.application(TGS_REQ, der.sequence(
        der.tagged(1, der.integer(PVNO)),
        der.tagged(2, der.integer(TGS_REQ)),
        der.tagged(3, der.sequenceOf([paTgs])),
        der.tagged(4, reqBody),
    ))

    return _parseRep(_sendReceive(kdcHost, kdcPort, tgsReq), tgt["sessionKey"], USAGE_TGS_REP_ENCPART, nonce, TGS_REP)

# ---- SPNEGO "Negotiate" token (cached service ticket -> ready-to-send HTTP token) -----------------
def spnegoFromTicket(service, realm, username):
    """Build a fresh SPNEGO token from an already-obtained service ticket (no KDC round-trip). Each
    call produces a new AP-REQ authenticator, as replay caches require, so a cached ticket can back
    every request of a scan cheaply."""

    enc = _enctype(service["sessionKeyType"])
    gssChecksum = (GSS_CHECKSUM_TYPE, struct.pack("<I", 16) + b"\x00" * 16 + struct.pack("<I", GSS_CHECKSUM_FLAGS))
    # seq-number is expected of the GSS mechanism's initial AP-REQ (RFC 4121), so always send one
    authenticator = _authenticator(realm, [username], cksum=gssChecksum, seqNumber=_nonce())
    encAuth = enc.encrypt(service["sessionKey"], USAGE_AP_REQ_AUTH, authenticator)
    return spnego.negTokenInit(_apReq(service["ticket"], encAuth, service["sessionKeyType"]))
