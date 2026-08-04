#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import hashlib
import hmac
import json
import re

from lib.core.convert import decodeBase64
from lib.core.convert import encodeBase64
from lib.core.convert import getBytes
from lib.core.convert import getText
from thirdparty import six

# a compact JSON Web Token: base64url(header).base64url(payload).base64url(signature); a header always starts
# with '{"' which base64url-encodes to the literal prefix 'eyJ', so this matches JWTs embedded in a larger value
JWT_REGEX = r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"

# keyed-hash algorithms sqlmap can both verify (crack) and forge offline
HMAC_ALGORITHMS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

def encodeSegment(value):
    return encodeBase64(json.dumps(value, separators=(',', ':')), binary=False, safe=True)

def parseJWT(token):
    """Split and decode a JWT into its header/payload/signature parts (None if it is not a well-formed JWT).

    >>> data = parseJWT("eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.")
    >>> data["header"]["alg"] == "none" and data["payload"]["user"] == "admin"
    True
    >>> parseJWT("not.a.jwt") is None
    True
    """

    if not token or token.count('.') != 2:
        return None

    header, payload, signature = token.split('.')

    try:
        header = json.loads(decodeBase64(header, binary=False))
        payload = json.loads(decodeBase64(payload, binary=False))
    except Exception:
        return None

    if not isinstance(header, dict) or not isinstance(header.get("alg"), six.string_types):
        return None

    return {"header": header, "payload": payload, "signature": signature, "signingInput": token.rsplit('.', 1)[0], "raw": token}

def findJWTs(value):
    """Return every well-formed JWT found inside an arbitrary value (e.g. a Cookie/Authorization header)."""

    return [match.group(0) for match in re.finditer(JWT_REGEX, value or "") if parseJWT(match.group(0))]

def forgeJWT(header, payload, key=None):
    """Re-encode a (possibly tampered) header/payload, signing with 'key' for an HMAC 'alg' or leaving the
    signature empty for 'alg':'none' - the primitive behind the alg:none and weak-secret exploitation paths.

    >>> forgeJWT({"alg": "none"}, {"user": "admin"}).endswith('.')
    True
    >>> parseJWT(forgeJWT({"alg": "HS256"}, {"user": "admin"}, key="secret"))["payload"]["user"] == "admin"
    True
    """

    alg = (header.get("alg") or "none")
    signingInput = "%s.%s" % (encodeSegment(header), encodeSegment(payload))

    if alg.lower() == "none":
        signature = ""
    elif alg.upper() in HMAC_ALGORITHMS and key is not None:
        digest = hmac.new(getBytes(key), getBytes(signingInput), HMAC_ALGORITHMS[alg.upper()]).digest()
        signature = encodeBase64(digest, binary=False, safe=True)
    else:
        raise ValueError("unsupported algorithm '%s' for forging" % alg)

    return "%s.%s" % (signingInput, signature)

def crackHMAC(token, secrets, limit=None):
    """Try to recover the HMAC signing secret of an HS* token from an iterable of candidate secrets; returns
    the secret on success (a full forgery primitive), else None. Purely offline - no requests.

    >>> token = forgeJWT({"alg": "HS256"}, {"user": "admin"}, key="s3cr3t")
    >>> crackHMAC(token, ["admin", "s3cr3t", "letmein"])
    's3cr3t'
    >>> crackHMAC(token, ["admin", "letmein"]) is None
    True
    """

    data = parseJWT(token)
    if not data or (data["header"].get("alg") or "").upper() not in HMAC_ALGORITHMS:
        return None

    fn = HMAC_ALGORITHMS[data["header"]["alg"].upper()]
    signingInput = getBytes(data["signingInput"])
    target = decodeBase64(data["signature"], binary=True)

    for index, secret in enumerate(secrets):
        if limit is not None and index >= limit:
            break
        secret = secret.strip() if hasattr(secret, "strip") else secret
        if hmac.new(getBytes(secret), signingInput, fn).digest() == target:
            return getText(secret)

    return None

def auditJWT(token, secrets=None, crackLimit=None):
    """Offline heuristic battery over a single JWT - the 'bad JWT setup' checks that bite in the real world and
    CTFs. Returns findings as (id, severity, summary, detail); online oracle checks (does the server ACCEPT an
    alg:none / bit-flipped / expired forgery) are layered on top by the caller, which owns response comparison.

    >>> sorted(_[0] for _ in auditJWT("eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."))
    ['alg-none', 'no-expiry']
    """

    findings = []
    data = parseJWT(token)
    if not data:
        return findings

    header, payload = data["header"], data["payload"]
    alg = (header.get("alg") or "").strip()

    # an unsigned token that the app already issued means forged claims need no key at all
    if alg.lower() == "none" or data["signature"] == "":
        findings.append(("alg-none", "critical", "token declares alg '%s' (unsigned)" % (alg or "none"), "claims can be forged with no key"))

    # a guessable HMAC secret is a full forgery primitive - crack it against the provided dictionary
    if alg.upper() in HMAC_ALGORITHMS and secrets is not None:
        secret = crackHMAC(token, secrets, crackLimit)
        if secret is not None:
            findings.append(("weak-hmac-secret", "critical", "HMAC secret recovered ('%s')" % secret, "arbitrary tokens can be forged and re-signed"))

    # an asymmetric token may be vulnerable to RS/HS confusion if the public key is retrievable
    if alg.upper().startswith(("RS", "ES", "PS")):
        findings.append(("alg-confusion", "info", "asymmetric algorithm '%s'" % alg, "test RS/HS confusion if the public key is obtainable (JWKS/TLS)"))

    # header fields that pull in attacker-controllable key material (CVE-2018-0114 class)
    for field in ("jku", "x5u", "jwk", "x5c"):
        if field in header:
            findings.append(("header-key-injection", "high", "header carries '%s'" % field, "attacker-hosted key material may be trusted"))

    # 'kid' commonly feeds a key lookup (file/DB/command) - a natural injection point
    if "kid" in header:
        findings.append(("kid-injection", "info", "header carries 'kid'", "candidate injection point (SQLi/LFI/path/command via key lookup)"))

    if isinstance(payload, dict) and "exp" not in payload:
        findings.append(("no-expiry", "high", "no 'exp' claim", "token does not expire"))

    return findings
