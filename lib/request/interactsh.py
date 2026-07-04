#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import base64
import json
import time

from lib.core.common import randomStr
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import HTTP_HEADER
from lib.core.settings import OOB_CORRELATION_ID_LENGTH
from lib.core.settings import OOB_INTERACTSH_SERVERS
from lib.core.settings import OOB_NONCE_LENGTH

# The interactsh client needs RSA-OAEP(SHA-256) + AES-256-CTR. pycryptodome is an
# optional dependency (sqlmap already uses it opportunistically in lib/utils/hash.py);
# without it the OOB tier is simply skipped rather than erroring.
try:
    from Crypto.Cipher import AES
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


def hasCrypto():
    return _HAS_CRYPTO


class Interactsh(object):
    """Minimal interactsh client: registers a per-scan RSA key with a public (or
    self-hosted) interactsh server, hands out unique callback URLs, and polls for
    the DNS/HTTP interactions they trigger. Interactions are RSA/AES encrypted on
    the wire and decrypted locally, so the server operator never sees their content.
    All HTTP goes through sqlmap's own request stack (proxy/timeout honoured)."""

    def __init__(self, server=None, token=None):
        self.server = None
        self.token = token or conf.get("oobToken")
        self.correlationId = randomStr(OOB_CORRELATION_ID_LENGTH, lowercase=True)
        self.secret = randomStr(32, lowercase=True)
        self.registered = False
        self._key = None
        self._dnsNonce = None

        if not _HAS_CRYPTO:
            return

        self._key = RSA.generate(2048)
        pubKey = getText(base64.b64encode(getBytes(self._key.publickey().export_key(format="PEM"))))
        candidates = [server] if server else list(OOB_INTERACTSH_SERVERS)

        for candidate in candidates:
            if not candidate:
                continue
            body = json.dumps({"public-key": pubKey, "secret-key": self.secret, "correlation-id": self.correlationId})
            if self._request("https://%s/register" % candidate, post=body):
                self.server = candidate
                self.registered = True
                logger.debug("registered with OOB interaction server '%s'" % candidate)
                break

    def _request(self, url, post=None):
        """Direct request to the interactsh server (a fixed service, never the target).
        Self-contained on urllib so it works regardless of sqlmap's request-stack init
        order (it is also called during option setup, before getPage is usable); honours
        --proxy and tolerates self-signed certs like the rest of sqlmap. Returns the
        response body text on success, otherwise None."""
        try:
            import ssl
            try:
                from urllib.request import Request as _Request, build_opener, ProxyHandler, HTTPSHandler
            except ImportError:
                from urllib2 import Request as _Request, build_opener, ProxyHandler, HTTPSHandler

            headers = {HTTP_HEADER.CONTENT_TYPE: "application/json"} if post is not None else {HTTP_HEADER.ACCEPT: "application/json"}
            if self.token:
                headers[HTTP_HEADER.AUTHORIZATION] = self.token

            handlers = []
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                handlers.append(HTTPSHandler(context=context))
            except Exception:
                pass
            if conf.get("proxy"):
                handlers.append(ProxyHandler({"http": conf.proxy, "https": conf.proxy}))

            request = _Request(url, data=getBytes(post) if post is not None else None, headers=headers)
            response = build_opener(*handlers).open(request, timeout=conf.get("timeout") or 30)
            return getText(response.read())
        except Exception as ex:
            logger.debug("OOB request to '%s' failed: %s" % (url, getText(ex)))
            return None

    def url(self):
        """Return a fresh unique callback URL (host = correlationId + nonce)."""
        nonce = randomStr(OOB_NONCE_LENGTH, lowercase=True)
        return "http://%s%s.%s" % (self.correlationId, nonce, self.server)

    def dnsDomain(self):
        """Stable domain suffix (host = correlationId + a fixed nonce) usable as an
        exfiltration suffix - additional labels prepended by a payload still resolve
        to this correlation id, so every DNS lookup under it is captured."""
        if not self._dnsNonce:
            self._dnsNonce = randomStr(OOB_NONCE_LENGTH, lowercase=True)
        return "%s%s.%s" % (self.correlationId, self._dnsNonce, self.server)

    def dnsNames(self):
        """Poll and return the fully-qualified names (minus the server suffix) of the
        DNS lookups captured so far, e.g. 'prefix.<hex>.suffix.<correlationId><nonce>'."""
        return [_.get("full-id") for _ in self.poll() if _.get("protocol") == "dns" and _.get("full-id")]

    def poll(self):
        """Return the list of decrypted interaction records captured so far."""
        if not self.registered:
            return []

        page = self._request("https://%s/poll?id=%s&secret=%s" % (self.server, self.correlationId, self.secret))
        if not page:
            return []

        try:
            response = json.loads(page)
        except ValueError:
            return []

        retVal = []
        data = response.get("data") or []
        if data:
            try:
                aesKey = PKCS1_OAEP.new(self._key, hashAlgo=SHA256).decrypt(base64.b64decode(response["aes_key"]))
            except Exception as ex:
                logger.debug("OOB AES key decryption failed: %s" % getText(ex))
                return []

            for item in data:
                try:
                    raw = base64.b64decode(item)
                    plain = AES.new(aesKey, AES.MODE_CTR, nonce=b"", initial_value=raw[:AES.block_size]).decrypt(raw[AES.block_size:])
                    retVal.append(json.loads(getText(plain)))
                except Exception as ex:
                    logger.debug("OOB interaction decryption failed: %s" % getText(ex))

        return retVal

    def pollUntil(self, attempts, delay):
        """Poll repeatedly, returning as soon as any interaction is captured."""
        for _ in range(attempts):
            time.sleep(delay)
            interactions = self.poll()
            if interactions:
                return interactions
        return []

    def close(self):
        if self.registered:
            body = json.dumps({"correlation-id": self.correlationId, "secret-key": self.secret})
            self._request("https://%s/deregister" % self.server, post=body)
            self.registered = False
