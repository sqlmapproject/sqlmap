#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Minimal GSS-API / SPNEGO (RFC 2743, RFC 4178) wrapping of a Kerberos AP-REQ into the token carried
# by the HTTP "Authorization: Negotiate <base64>" header. Only the initiator's NegTokenInit is built
# (the one-shot token an HTTP client sends); the mechanism-specific OIDs are fixed constants.
# Python 2.7 / 3.x.

from extra.kerberos import der

# fully-encoded OBJECT IDENTIFIER TLVs
KRB5_OID = bytes(bytearray([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]))  # 1.2.840.113554.1.2.2
SPNEGO_OID = bytes(bytearray([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]))                  # 1.3.6.1.5.5.2

TOK_ID_AP_REQ = b"\x01\x00"                                # GSS Kerberos token id for KRB_AP_REQ

def gssApReq(apReq):
    """GSS InitialContextToken: [APPLICATION 0] { Kerberos OID, tok-id, AP-REQ }."""

    return der.application(0, KRB5_OID + TOK_ID_AP_REQ + apReq)

def negTokenInit(apReq):
    """SPNEGO NegTokenInit wrapping the Kerberos GSS token (Kerberos advertised as the sole mech)."""

    inner = der.sequence(
        der.tagged(0, der.sequenceOf([KRB5_OID])),         # mechTypes
        der.tagged(2, der.octetString(gssApReq(apReq))),   # mechToken
    )
    return der.application(0, SPNEGO_OID + der.tagged(0, inner))
