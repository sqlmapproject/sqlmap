#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import base64
import collections
import threading
import json
import time
import hashlib

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
        self._poller = None
        # Guards the poller create/start decision so two callers racing on an unstarted
        # session cannot each build their own poller and destructively poll one session.
        self._pollerLock = threading.Lock()
        # Set under _pollerLock while stop() tears down: blocks _ensurePoller from restarting the
        # poller in the gap between stop() and close()/deregister().
        self._stopping = False

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
                # Verify TLS for the (public, valid-cert) interaction server by default;
                # only skip verification when the user has globally opted out (--force-ssl-verify
                # off / verifyCert False), matching sqlmap's own TLS posture.
                context = ssl.create_default_context()
                if conf.get("verifyCert") is False:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                handlers.append(HTTPSHandler(context=context))
            except Exception:
                pass
            if conf.get("proxy"):
                handlers.append(ProxyHandler({"http": conf.proxy, "https": conf.proxy}))

            request = _Request(url, data=getBytes(post) if post is not None else None, headers=headers)
            # request_timeout() is the single source of truth for every interactsh network op so
            # InteractshPoller.stop() can join for exactly one /poll network call.
            response = build_opener(*handlers).open(request, timeout=self.request_timeout())
            return getText(response.read())
        except Exception as ex:
            logger.debug("OOB request to '%s' failed: %s" % (url, getText(ex)))
            return None

    def request_timeout(self):
        """Network timeout (seconds) applied to every /poll and /deregister request. Interactsh
        derives its /poll network timeout identically, so InteractshPoller.stop() can join for
        exactly one of these before the thread is guaranteed to have exited."""
        return conf.get("timeout") or _DEFAULT_NETWORK_TIMEOUT

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
        """Return the fully-qualified names (minus the server suffix) of the DNS lookups
        captured so far, e.g. 'prefix.<hex>.suffix.<correlationId><nonce>'.

        This is a *snapshot* over the single background poller's in-memory queue: it ensures the
        poller is running and drains whatever it has already staged, so it does not itself issue
        a fresh /poll. On the very first call after registration the poller may not have finished
        its first round-trip yet and can therefore return [] even though interactions exist -
        retry the call rather than treating that first call as authoritative."""
        return [_.get("full-id")
                for _ in self._consume(
                    lambda _: _.get("protocol") == "dns" and _.get("full-id"),
                    None)]

    def httpRequests(self):
        """Return the captured HTTP interactions (collector half of an HTTP-based out-of-band
        data channel). Unlike DNS, where the value rides the queried hostname, an HTTP callback
        carries its payload in the request line/body - so the interaction itself is the evidence.

        interactsh stores each record with a ``raw-request`` (the full dumped request), a
        ``protocol`` (``http`` or ``https``) and a ``remote-address`` - it does not pre-parse the
        path/query. A value with no safe-in-URL character set is therefore embedded in a
        query-string *parameter name* (the path stays a constant request line and only the
        attacker-controlled name varies) and the decoded names are returned here.
        """
        retVal = []

        for _ in self._consume(lambda _: _.get("protocol") in ("http", "https"), None):
            retVal.append(self._renderHttpRequest(_))

        return retVal

    def _renderHttpRequest(self, record):
        interaction = {
            "full-id": record.get("full-id") or "",
            "client": record.get("remote-address") or record.get("client") or "",
            "request": record.get("raw-request") or "",
            "query-param-names": [],
        }

        raw = interaction["request"]
        target = _parseHttpRequestTarget(raw) if raw else (record.get("full-id") or "")
        if target:
            interaction["query-param-names"] = _extractQueryStringNames(target)

        return interaction

    def _ensurePoller(self):
        """Start the single background /poll consumer (idempotent). The poller is the only code
        that calls the remote endpoint; DNS/HTTP consumers then read the same records from
        memory, so they never drain each other. No-op without crypto, since /poll cannot then be
        decrypted."""
        if not _HAS_CRYPTO:
            return

        # The whole create-or-reuse-and-start sequence is under one lock, so exactly one
        # background poller is ever created and started for this session. A poller must only run
        # for a live, registered session: skip if the session was never registered, and skip if
        # stop() is in progress (so no poller can be restarted between stop() and deregister()).
        with self._pollerLock:
            if not self.registered or self._stopping:
                return
            poller = getattr(self, "_poller", None)
            if poller is None:
                self._poller = poller = InteractshPoller(self)
            if not poller.isRunning():
                poller.start()

    def _consume(self, selector, deadline=None, sync=False):
        """Return records matching selector.

        For normal registered operation the single background poller drains the remote session
        (zero extra network calls from the consumer, and exactly one caller ever drains it), so
        we ensure it is running and read its in-memory queue. ``sync=True`` forces the direct
        ``poll()`` path for the deprecated fallback / explicit testing.

        ``deadline`` is an absolute timestamp: ``None`` drains the current queue only (no wait),
        used by snapshot-style callers such as ``httpRequests``/``dnsNames``.

        Outside ``sync=True`` only the background poller ever calls the remote ``poll()`` - the
        invariant this method enforces. A stale poller (never started, or started then stopped by
        ``stop()``) yields ``[]`` rather than a second, unsynchronised ``poll()`` that could
        destructively drain the shared session from the wrong caller.

        ``sync=True`` forces the direct-poll path, but only for a live, registered session that
        has no background poller already draining it - the poller is the only code that is allowed
        to call the remote endpoint, so a spurious ``sync=True`` during normal operation drains the
        running poller's queue instead of adding a second destructive ``poll()`` caller. Once
        ``stop()`` has begun, no caller initiates another remote ``poll()`` - not this
        compatibility path either."""
        if sync:
            with self._pollerLock:
                if self._stopping or not self.registered:
                    return []
                poller = getattr(self, "_poller", None)
                if poller is None or not poller.isRunning():
                    # Keep the lock across this compatibility poll so _ensurePoller() cannot start
                    # a background poller concurrently in the gap between the check and poll()
                    # (which would then become a second /poll caller).
                    return [record for record in self.poll() if self._safeSelector(selector, record)]
            # Releasing the lock before draining the poller's queue keeps _ensurePoller() free too.
            return poller.drain_matching(selector, deadline)

        self._ensurePoller()
        poller = getattr(self, "_poller", None)
        if poller is not None and poller.isRunning():
            return poller.drain_matching(selector, deadline)
        return []

    def _safeSelector(self, selector, record):
        try:
            return bool(selector(record))
        except Exception as ex:
            logger.debug("interactsh selector error: %s" % getText(ex))
            return False

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
        """Wait for and return captured interactions, up to attempts * delay seconds.

        The background poller remains the sole remote /poll consumer. Each attempt waits on its
        in-memory queue for at most ``delay`` seconds instead of issuing an independent destructive
        poll() request.
        """
        for _ in range(attempts):
            interactions = self._consume(lambda record: True, deadline=time.time() + delay)
            if interactions:
                return interactions
        return []

    def stop(self):
        """Stop the background poller (join it) then deregister the interaction.

        The poller is the only code that drains the remote /poll session, so it must be
        stopped before deregistering; stopping it first also prevents it from re-staging
        interactions after close() is called (best-effort on a dead/broken poller).

        Normal completion leaves no active polling thread. If the poller cannot be joined within
        one request-timeout budget, this interaction is deliberately left registered so deregister
        never races a still-active /poll drain; a later stop()/close() retries the join and
        deregisters once the thread has exited."""
        # Set _stopping and capture the poller under _pollerLock (the start/stop race lives under
        # that lock); release the lock before joining so a concurrent _ensurePoller() caller is
        # not blocked for a whole join. The lock prevents a restart of this same poller between here
        # and deregister(); only the (now-dead) poller is joined.
        poller = None
        with self._pollerLock:
            self._stopping = True
            poller = getattr(self, "_poller", None)
        stopped = True
        if poller is not None:
            try:
                stopped = poller.stop()
            except Exception:
                logger.debug("error while stopping interactsh poller")
                stopped = False
        if not stopped:
            # A /poll network call is still draining the session; skip deregister this time and let
            # the next stop()/close() deregister once the thread has actually exited.
            return
        self._deregister()

    def close(self):
        """Canonical complete teardown: stop the poller AND deregister.

        close() predates the background-poller addition, so existing callers can keep using it
        without learning about stop(). If the current /poll cannot be joined within its bounded
        network-timeout budget, teardown remains pending and the interaction stays registered so
        a later close()/stop() can retry safely."""
        self.stop()

    def _deregister(self):
        if self.registered:
            body = json.dumps({"correlation-id": self.correlationId, "secret-key": self.secret})
            self._request("https://%s/deregister" % self.server, post=body)
            self.registered = False


# Delay between two remote /poll round-trips in the background poller.
_POP_POLL_DELAY = 1.0

# Network timeout (seconds) applied to each interactsh /poll and /deregister request (see
# Interactsh._request). InteractshPoller.stop() joins for one of these (with a little slack) so a
# /poll wedged at the remote endpoint cannot keep a dead poller's thread alive past stop().
_DEFAULT_NETWORK_TIMEOUT = 30


def _parseHttpRequestTarget(raw_request):
    """Return the request target (undecoded) from the first line of a raw HTTP request.

    It is deliberately left raw: decoding before splitting on '&'/'=' would corrupt encoded
    delimiters (a value with an unsafe-in-URL character set may hit the same host as its own
    name, e.g. ``?aa%26bb=1`` must parse to one name ``aa&bb``, not two). Downstream code decodes
    each name individually.
    """
    if not raw_request:
        return ""
    first_line = raw_request.splitlines()[0]
    parts = first_line.split(None, 2)
    if len(parts) >= 2:
        target = parts[1]
    else:
        target = first_line
    return target


def _unquote(value):
    try:
        from urllib import unquote
    except ImportError:
        from urllib.parse import unquote
    return unquote(value)


def _extractQueryStringNames(raw_target):
    """Return the ordered, de-duplicated query-string parameter names from a raw (undecoded) target.

    Split the raw target on literal '&' and the first raw '=', then percent-decode only each
    parameter name individually so encoded delimiters (``%26`` '&', ``%3D`` '=', ``%25`` '%') are
    preserved in the decoded name rather than misinterpreted as structure.
    """
    try:
        query = raw_target.split("?", 1)[1]
    except IndexError:
        return []
    names = []
    for pair in query.split("&"):
        if not pair:
            continue
        encoded_name = pair.split("=", 1)[0]
        name = _unquote(encoded_name)
        if name and name not in names:
            names.append(name)
    return names


class InteractshPoller(object):
    """A single background consumer of one interactsh session: one thread polls /poll and queues
    complete interaction records under a Condition, so the DNS and HTTP consumers read the same
    records from memory without ever calling the remote endpoint twice or draining each other."""

    def __init__(self, client):
        self._client = client
        self._queue = collections.deque()
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._seen = set()
        self._running = False
        self._thread = None

    def start(self):
        """Start the poller (idempotent)."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._loop)
            self._thread.daemon = True
            self._thread.start()

    def stop(self):
        """Stop the poller and join the thread until it actually exits.

        Returns True if the poll thread has exited, False if it could not be stopped within the
        budget (its in-flight /poll request is still running). stop() flips _running and wakes the
        loop, so the thread exits after its current /poll returns - join therefore only has to
        outlast one /poll network operation, whose timeout is derived from the client's request
        timeout. Joining is retried on every call, so a second stop() after a failed first still
        joins the (now-sleeping-loop) thread instead of bailing out before _running was read.

        Only a genuinely hung /poll network call exceeds the budget; the common case exits as soon
        as the loop wakes. On timeout this method returns False and the owner leaves the interaction
        registered; a later stop() retries joining the same thread."""
        with self._lock:
            self._running = False
            self._cond.notify_all()
            thread = self._thread
        if not thread or not thread.is_alive():
            return True
        # stop() has already woken the loop, so the thread exits after its current /poll returns.
        # One join that outlasts one /poll network call is enough; the slack covers the loop's own
        # work before it re-checks _running. A hung request is guarded by retrying stop().
        fn = getattr(self._client, "request_timeout", None)
        network_timeout = fn() if callable(fn) else _DEFAULT_NETWORK_TIMEOUT
        thread.join(network_timeout + _POP_POLL_DELAY)
        return not thread.is_alive()

    def isRunning(self):
        return self._running and self._thread is not None and self._thread.is_alive()

    def _loop(self):
        while self._running:
            try:
                records = self._client.poll()
                with self._cond:
                    # Recheck _running after poll() returns: stop() may have set it False while the
                    # network call was in flight. Drop the just-received records without staging
                    # them, so a stopped poller can never repopulate its queue after shutdown.
                    if not self._running:
                        break
                    for record in records:
                        # Only queue interaction protocols sqlmap consumes (dns/http/https). Other
                        # interaction types (smtp/ldap/...) would never be drained by sqlmap's
                        # consumers and would otherwise accumulate in _queue for the whole session;
                        # bounding the queue to what we actually use keeps it from growing.
                        if record.get("protocol") not in ("dns", "http", "https"):
                            continue
                        # Fingerprint the *interaction*, not the payload host ("full-id").
                        # protocol + full-id + unique-id only identify the receiving subdomain
                        # (a single host drives many interactions); timestamp is a separate, per-
                        # interaction field that keeps two identical requests to that host distinct.
                        # Per-record try: a malformed interaction (a non-string field making the
                        # join raise, or a bytes value getBytes() cannot decode) throws here. Keeping
                        # it inside the per-record handler means one odd interaction skips itself
                        # without aborting every later interaction in the already-drained batch, which
                        # the outer batch-level except would otherwise do.
                        try:
                            rid_str = "|".join((record.get("protocol") or "",
                                                 record.get("full-id") or "",
                                                 record.get("unique-id") or "",
                                                 record.get("timestamp") or "",
                                                 record.get("raw-request") or "",
                                                 record.get("remote-address") or ""))
                            # Hash before storing so _seen never retains a full raw-request (bounded
                            # to a fixed-length hexdigest); the review noted raw-request retention
                            # grew _seen for the whole session. Hashlib is only consulted when we
                            # have a record to fingerprint.
                            rid = hashlib.sha256(getBytes(rid_str)).hexdigest()
                        except Exception as ex:
                            logger.debug("interactsh fingerprint error: %s" % getText(ex))
                            continue
                        if rid in self._seen:
                            continue
                        self._seen.add(rid)
                        self._queue.append(record)
                        self._cond.notify_all()
            except Exception as ex:
                logger.debug("interactsh poller poll error: %s" % getText(ex))
            if self._running:
                time.sleep(_POP_POLL_DELAY)

    def _safeSelector(self, selector, record):
        try:
            return bool(selector(record))
        except Exception as ex:
            logger.debug("interactsh selector error: %s" % getText(ex))
            return False

    def drain_matching(self, selector, deadline=None):
        """Return all currently-queued records matching selector (removing them).

        ``deadline=None`` drains the current queue with no wait (snapshot-style callers such as
        ``httpRequests``/``dnsNames``); only ``InteractshDNSServer.pop`` passes an absolute
        deadline to wait for new arrivals. The wait and the scan share one condition critical
        section so a producer cannot enqueue+notify between releasing and reacquiring the lock,
        which would otherwise stall another 0.5 s even when a match already exists."""
        while True:
            with self._cond:
                matched = [record for record in self._queue if self._safeSelector(selector, record)]
                if matched:
                    for record in matched:
                        self._queue.remove(record)
                    return matched
                # Check _running before the first wait as well: stop() may have fired between the
                # scan and a wait() call, so the matching notification has already happened - a bare
                # wait() would otherwise sleep the whole budget for nothing.
                if not self._running:
                    return []
                if deadline is None:
                    return []
                remaining = deadline - time.time()
                if remaining <= 0:
                    return []
                self._cond.wait(timeout=remaining)
                # Wake-up was not for a match; if stop() fired in the meantime no producer can
                # ever enqueue one, so exit promptly instead of looping for the full deadline.
                if not self._running:
                    return []
