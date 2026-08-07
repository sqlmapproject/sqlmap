#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Coverage for the HTTP/2 timeless-timing oracle in lib/request/timeless.py: the
sequential decision engine that turns response-order votes into bits, the pair
transport's replay-safety and response validation, request-spec conversion, the
sentinel negation, and oracle teardown.

Network-free - a fake _H2Connection stands in for the transport, so every vote
sequence is exactly reproducible.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.request import timeless as _timeless
from lib.request.http2 import _UnprocessedStream
from lib.request.timeless import (
    LIGHT_HEAVY,
    LIGHT_HEAVY_COSTS,
    SPRT_CAP_FACTOR,
    TimelessOracle,
    TimelessUnusable,
    _pairOrder,
    _specToReq,
    buildConditionPair,
    calibrate,
    lightHeavyVector,
    negateCondition,
    negatePayload,
    readBit,
)

REQ_COND = {"method": "GET", "path": "/?id=1", "authority": "h"}
REQ_NEG = {"method": "GET", "path": "/?id=2", "authority": "h"}


class FakeConnection(object):
    """Minimal _H2Connection stand-in. `orders` is an iterable of booleans - True means the SECOND request
    of the pair finished last (so exchange_pair reports the first-sent stream as finishing first)."""

    def __init__(self, orders=(), statuses=None, raises=None, host="target"):
        self.host, self.port = host, 443
        self.next_sid = 1
        self.usable = True
        self.closed = 0
        self.sent = []
        self._orders = list(orders)
        self._statuses = list(statuses) if statuses is not None else None
        self._raises = list(raises) if raises is not None else []

    def exchange_pair(self, requests, timeout):
        if self._raises:
            error = self._raises.pop(0)
            if error is not None:
                raise error
        self.sent.append(list(requests))
        lo, hi = self.next_sid, self.next_sid + 2
        self.next_sid += 4
        secondLast = self._orders.pop(0) if self._orders else True
        order = [lo, hi] if secondLast else [hi, lo]
        status = self._statuses.pop(0) if self._statuses else 200
        statuses = status if isinstance(status, tuple) else (status, status)
        return order, {lo: (statuses[0], [], b""), hi: (statuses[1], [], b"")}

    def close(self):
        self.closed += 1
        self.usable = False


def votes(*heavyLast):
    """Build the `orders` sequence for readBit()/calibrate() votes: heavyLast[i] True means the request
    under test (reqCond / reqSlow) finished LAST on vote i. Both alternate the send order, so which slot it
    occupies - and therefore whether 'it finished last' means 'the second-sent stream finished last' -
    flips every vote."""
    return [last if i % 2 else not last for i, last in enumerate(heavyLast)]


class TimelessDecisionTest(unittest.TestCase):
    def test_unanimous_true_and_false(self):
        conn = FakeConnection(votes(*([True] * 20)))
        self.assertTrue(readBit(conn, REQ_COND, REQ_NEG, votes=4))
        conn = FakeConnection(votes(*([False] * 20)))
        self.assertFalse(readBit(conn, REQ_COND, REQ_NEG, votes=4))

    def test_decisions_only_on_balanced_samples(self):
        """Both stream-id orderings must contribute equally, so a bit can never be decided on an odd
        number of votes (which would give one ordering an extra say)."""
        for pattern in ([True] * 20, [False] * 20, [True, False] * 10):
            conn = FakeConnection(votes(*pattern))
            readBit(conn, REQ_COND, REQ_NEG, votes=4)
            self.assertEqual(len(conn.sent) % 2, 0)

    def test_late_disagreement_does_not_flip_a_true_bit(self):
        """The regression the sequential test fixes: three cond-last then two cond-first used to hit
        fraction 0.6 -> escalate, and the next cond-first (3/6 = 0.5) returned False on the spot."""
        pattern = [True, True, True, False, False, False] + [True] * 30
        conn = FakeConnection(votes(*pattern))
        self.assertTrue(readBit(conn, REQ_COND, REQ_NEG, votes=4))
        self.assertGreater(len(conn.sent), 6)

    def test_coin_flip_reads_false(self):
        """A DBMS that errors past the end of a string makes both requests error, so the order is a coin
        flip - that must terminate the string, not invent a character."""
        conn = FakeConnection(votes(*([True, False] * 40)))
        self.assertFalse(readBit(conn, REQ_COND, REQ_NEG, votes=4))

    def test_cap_is_respected(self):
        conn = FakeConnection(votes(*([True, False] * 200)))
        readBit(conn, REQ_COND, REQ_NEG, votes=4)
        self.assertLessEqual(len(conn.sent), 4 * SPRT_CAP_FACTOR)

    def test_clean_model_costs_no_more_than_the_classic_rule(self):
        """A target whose tuning sweep was unanimous is read at SPRT_P_TRUE_CLEAN. Live measurement on such
        a target (6990 votes, idle and under 4x load) never produced a disagreeing vote, so the model has to
        pay about what the old fixed five-pair rule did or the accuracy work is a straight slowdown."""
        conn = FakeConnection(votes(*([True] * 20)))
        self.assertTrue(readBit(conn, REQ_COND, REQ_NEG, votes=4, pTrue=_timeless.SPRT_P_TRUE_CLEAN))
        self.assertLessEqual(len(conn.sent), 6)

        conn = FakeConnection(votes(*([False] * 20)))
        self.assertFalse(readBit(conn, REQ_COND, REQ_NEG, votes=4, pTrue=_timeless.SPRT_P_TRUE_CLEAN))
        self.assertLessEqual(len(conn.sent), 4)

    def test_clean_model_still_terminates_a_string(self):
        """The end-of-string coin flip is the failure this engine exists to prevent, so it must hold under
        the cheaper model too."""
        conn = FakeConnection(votes(*([True, False] * 60)))
        self.assertFalse(readBit(conn, REQ_COND, REQ_NEG, votes=4, pTrue=_timeless.SPRT_P_TRUE_CLEAN))

    def test_minimum_sample_is_honoured(self):
        conn = FakeConnection(votes(*([False] * 40)))
        readBit(conn, REQ_COND, REQ_NEG, votes=12)
        self.assertGreaterEqual(len(conn.sent), 12)

    def test_error_rates_are_bounded(self):
        """Drive the decision engine with a deterministic pseudo-random vote stream and check that the
        realised error rate on both hypotheses stays inside the configured bound (with slack for the
        finite cap)."""
        def stream(p, seed, count):
            state, out = seed, []
            for _ in range(count):
                state = (1103515245 * state + 12345) % (1 << 31)
                out.append((state >> 16) % 1000 < p * 1000)
            return out

        wrong = 0
        for trial in range(60):             # genuine TRUE bits at the modelled per-vote reliability
            conn = FakeConnection(votes(*stream(_timeless.SPRT_P_TRUE, trial + 1, 2000)))
            wrong += not readBit(conn, REQ_COND, REQ_NEG, votes=4)
        self.assertLessEqual(wrong, 6)      # bound is 2%, allow slack for the finite sample

        wrong = 0
        for trial in range(60):             # end-of-string coin flip: must never invent a character
            conn = FakeConnection(votes(*stream(0.5, trial + 1, 2000)))
            wrong += bool(readBit(conn, REQ_COND, REQ_NEG, votes=4))
        self.assertLessEqual(wrong, 6)

        wrong = 0
        for trial in range(60):             # real FALSE bits (cond is strictly the cheap one)
            conn = FakeConnection(votes(*stream(0.02, trial + 1, 2000)))
            wrong += bool(readBit(conn, REQ_COND, REQ_NEG, votes=4))
        self.assertEqual(wrong, 0)


class TimelessTransportTest(unittest.TestCase):
    def test_unprocessed_stream_is_retried_on_a_factory(self):
        conns = [FakeConnection([True], raises=[_UnprocessedStream("goaway")]), FakeConnection([True])]
        made = []

        def factory():
            made.append(conns[len(made)])
            return made[-1]

        first, loSid, hiSid, status = _pairOrder(factory, REQ_COND, REQ_NEG, 5)
        self.assertEqual(len(made), 2)
        self.assertEqual(status, 200)
        self.assertEqual((loSid, hiSid), (1, 3))
        self.assertEqual(first, loSid)

    def test_ambiguous_transport_error_is_not_replayed(self):
        """A generic drop proves nothing about whether the application saw the requests - re-sending it
        could re-run a state-changing injection point."""
        conn = FakeConnection([True], raises=[socket.error("connection reset")])
        self.assertRaises(socket.error, _pairOrder, lambda: conn, REQ_COND, REQ_NEG, 5)
        self.assertEqual(conn.closed, 1)

    def test_status_mismatch_between_streams_raises(self):
        conn = FakeConnection([True] * 8, statuses=[(200, 403)] * 8)
        self.assertRaises(TimelessUnusable, _pairOrder, conn, REQ_COND, REQ_NEG, 5)

    def test_drift_from_the_calibrated_status_raises(self):
        conn = FakeConnection([True] * 8, statuses=[302] * 8)
        self.assertRaises(TimelessUnusable, _pairOrder, conn, REQ_COND, REQ_NEG, 5, expectStatus=200)

    def test_transient_status_blip_is_tolerated(self):
        conn = FakeConnection([True] * 8, statuses=[500, 200])
        _first, _lo, _hi, status = _pairOrder(conn, REQ_COND, REQ_NEG, 5, expectStatus=200)
        self.assertEqual(status, 200)

    def test_calibrate_reports_the_control_status(self):
        conn = FakeConnection(votes(*([True] * 10)), statuses=[201] * 10)
        usable, confidence, status = calibrate(conn, REQ_COND, REQ_NEG, trials=10)
        self.assertTrue(usable)
        self.assertEqual(confidence, 1.0)
        self.assertEqual(status, 201)

    def test_calibrate_rejects_a_serializing_backend(self):
        conn = FakeConnection([True] * 20)              # order tracks arrival, not work
        usable, confidence, _status = calibrate(conn, REQ_COND, REQ_NEG, trials=10)
        self.assertFalse(usable)
        self.assertLess(confidence, 0.9)


class TimelessSpecTest(unittest.TestCase):
    def test_authority_comes_from_the_host_header(self):
        spec = ("https://10.0.0.5/path?a=1", "GET", {"Host": "vhost.example", "X-A": "1"}, None)
        req = _specToReq(spec, "fallback")
        self.assertEqual(req["authority"], "vhost.example")
        self.assertEqual(req["path"], "/path?a=1")

    def test_authority_falls_back_to_the_url(self):
        spec = ("https://10.0.0.5/path", "GET", {"X-A": "1"}, None)
        self.assertEqual(_specToReq(spec, "fallback")["authority"], "10.0.0.5")

    def test_connection_nominated_fields_reach_the_http2_normalizer(self):
        """Stripping Connection here would leave the fields it names in the h2 request, which is
        malformed - the HTTP/2 layer needs to see it to remove them."""
        spec = ("https://h/p", "GET", {"Connection": "X-Remove", "X-Remove": "v"}, None)
        req = _specToReq(spec, "h")
        self.assertIn("Connection", req["headers"])

        from lib.request.http2 import _normalize_request_headers
        names = [name for name, _value in _normalize_request_headers(req["headers"], b"")]
        self.assertNotIn(b"x-remove", names)
        self.assertNotIn(b"connection", names)

    def test_userinfo_is_dropped_from_the_authority(self):
        spec = ("https://user:pass@host.example:8443/p", "GET", {}, None)
        self.assertEqual(_specToReq(spec, "h")["authority"], "host.example:8443")


class TimelessPayloadTest(unittest.TestCase):
    def test_negation_spans_newlines(self):
        value = "AND 1=(CASE WHEN (%sASCII(SUBSTR(x,\n1,1))>64%s) THEN 1 ELSE 1 END)" % (
            _timeless.INFERENCE_BEGIN, _timeless.INFERENCE_END)
        negated = negatePayload(value)
        self.assertIsNotNone(negated)
        self.assertIn("ASCII(SUBSTR(x,\n1,1))>64", negated)
        self.assertIn("THEN 1 ELSE 0 END)=0", negated)

    def test_negation_requires_sentinels(self):
        self.assertIsNone(negatePayload("AND 1=1"))
        self.assertIsNone(negatePayload(None))

    def test_negation_is_null_safe(self):
        """Plain NOT() would leave both requests cheap at end-of-string (NOT NULL is NULL), so neither
        branch runs heavy and the order is noise."""
        self.assertNotIn("NOT(", negateCondition("ORD(x)>64"))
        self.assertEqual(negateCondition("ORD(x)>64"), "(CASE WHEN (ORD(x)>64) THEN 1 ELSE 0 END)=0")

    def test_every_primitive_consumes_the_cost(self):
        """A primitive that ignores [COST] makes every rung of the ladder send the identical query while
        reporting a different cost."""
        for dbms, primitive in LIGHT_HEAVY.items():
            self.assertIn("[COST]", primitive, "%s primitive ignores [COST]" % dbms)

    def test_every_primitive_yields_a_sentinel_vector(self):
        for dbms in LIGHT_HEAVY:
            vector = lightHeavyVector(dbms, LIGHT_HEAVY_COSTS[0])
            self.assertIn(_timeless.INFERENCE_BEGIN, vector)
            self.assertIn(_timeless.INFERENCE_END, vector)
            self.assertIsNotNone(negatePayload(vector))

    def test_condition_pair_runs_heavy_exactly_once(self):
        cond, neg = buildConditionPair("ORD(x)>64", "HEAVY")
        self.assertEqual(cond.count("HEAVY"), 1)
        self.assertEqual(neg.count("HEAVY"), 1)
        self.assertNotEqual(cond, neg)


class TimelessOracleTest(unittest.TestCase):
    def _oracle(self, connections, **kwargs):
        oracle = TimelessOracle("h", 443, REQ_COND, REQ_NEG, votes=4, status=200, **kwargs)
        made = []

        def opener(host, port, proxy, timeout):
            made.append(connections[len(made)])
            return made[-1]

        oracle._opened = made
        _timeless.connect, self._savedConnect = opener, _timeless.connect
        return oracle

    def tearDown(self):
        if hasattr(self, "_savedConnect"):
            _timeless.connect = self._savedConnect
            del self._savedConnect

    def test_a_fresh_connection_is_calibrated_before_it_reads(self):
        conn = FakeConnection(votes(*([True] * 40)))
        oracle = self._oracle([conn])
        oracle._conn()
        self.assertEqual(len(conn.sent), _timeless.VERIFY_TRIALS)

    def test_a_serializing_replacement_connection_is_refused(self):
        """The initial sweep proves one connection to one backend node; a later connection can land on a
        node that serializes streams and would return wrong bits without ever raising."""
        conn = FakeConnection([True] * 40)              # first-sent always finishes first
        oracle = self._oracle([conn])
        self.assertRaises(TimelessUnusable, oracle._conn)
        self.assertEqual(conn.closed, 1)
        self.assertEqual(oracle._conns, [])

    def test_close_does_not_resurrect_a_concurrently_opened_connection(self):
        conn = FakeConnection(votes(*([True] * 40)))
        oracle = self._oracle([conn])
        started, release = threading.Event(), threading.Event()
        opener = _timeless.connect

        def blocking(*args, **kwargs):
            started.set()
            release.wait(5)
            return opener(*args, **kwargs)

        _timeless.connect = blocking
        worker = threading.Thread(target=lambda: self.assertRaises(TimelessUnusable, oracle._conn))
        worker.daemon = True
        worker.start()
        started.wait(5)
        oracle.close()                      # closes while the worker is still inside connect()
        release.set()
        worker.join(5)
        self.assertEqual(oracle._conns, [])
        self.assertEqual(conn.closed, 1)

    def test_clean_model_demands_a_unanimous_connection(self):
        """The cheap model is only sound where votes are deterministic, so a connection that cannot
        reproduce the unanimity the tuning sweep saw must not be read at it."""
        oneMiss = votes(*([True] * 3 + [False] + [True] * 40))
        oracle = self._oracle([FakeConnection(oneMiss)], verifyThreshold=_timeless.VERIFY_THRESHOLD_CLEAN,
                              pTrue=_timeless.SPRT_P_TRUE_CLEAN)
        self.assertRaises(TimelessUnusable, oracle._conn)

        oracle = self._oracle([FakeConnection(oneMiss)])         # conservative model tolerates it
        self.assertTrue(oracle._conn())

    def test_close_is_idempotent(self):
        conn = FakeConnection(votes(*([True] * 40)))
        oracle = self._oracle([conn])
        oracle._conn()
        oracle.close()
        oracle.close()
        self.assertEqual(conn.closed, 1)


class TimelessEngagementTest(unittest.TestCase):
    """engage()/disengage() are the state machine the runtime fallback depends on. Restoring the vector
    alone is NOT enough - bisection freezes a comparison template from it when a value starts extracting,
    so disengage() must also publish the classic vector for queryPage to re-forge the stragglers with,
    or the rest of that value keeps sending heavy (no-delay) payloads that read as all-False."""

    def setUp(self):
        from lib.core.data import kb
        from lib.core.datatype import AttribDict
        from lib.core.enums import PAYLOAD

        self.kb, self.technique = kb, PAYLOAD.TECHNIQUE.TIME
        self._saved = (kb.get("injection"), kb.get("timeless"), kb.get("timelessRestore"))
        kb.injection = AttribDict({"data": AttribDict({self.technique: AttribDict({"vector": "AND SLEEP([SLEEPTIME]) [INFERENCE]"})})})
        kb.timeless = None
        kb.timelessRestore = None

    def tearDown(self):
        self.kb.injection, self.kb.timeless, self.kb.timelessRestore = self._saved

    def _oracle(self):
        return TimelessOracle("h", 443, REQ_COND, REQ_NEG, status=200)

    def test_engage_swaps_the_vector_and_publishes_last(self):
        oracle = self._oracle()
        _timeless.engage(oracle, self.technique, "AND HEAVY [INFERENCE]")
        self.assertEqual(self.kb.injection.data[self.technique].vector, "AND HEAVY [INFERENCE]")
        self.assertIs(self.kb.timeless, oracle)
        self.assertIsNone(self.kb.timelessRestore)

    def test_disengage_restores_and_arms_the_straggler_rewrite(self):
        oracle = self._oracle()
        _timeless.engage(oracle, self.technique, "AND HEAVY [INFERENCE]")
        _timeless.disengage()
        self.assertEqual(self.kb.injection.data[self.technique].vector, "AND SLEEP([SLEEPTIME]) [INFERENCE]")
        self.assertIsNone(self.kb.timeless)
        self.assertEqual(self.kb.timelessRestore, "AND SLEEP([SLEEPTIME]) [INFERENCE]")

    def test_re_engaging_clears_a_previous_targets_rewrite(self):
        """A stale rewrite vector outliving its target would re-forge the next one's payloads."""
        _timeless.engage(self._oracle(), self.technique, "AND HEAVY [INFERENCE]")
        _timeless.disengage()
        self.assertIsNotNone(self.kb.timelessRestore)
        _timeless.engage(self._oracle(), self.technique, "AND HEAVY2 [INFERENCE]")
        self.assertIsNone(self.kb.timelessRestore)

    def test_disengage_holds_the_data_object_not_the_technique(self):
        """disengage() can run after the controller moved to the next target; re-resolving the technique
        then would restore this target's vector onto the next one's injection data."""
        from lib.core.datatype import AttribDict

        oracle = self._oracle()
        _timeless.engage(oracle, self.technique, "AND HEAVY [INFERENCE]")
        stale = self.kb.injection.data[self.technique]
        self.kb.injection = AttribDict({"data": AttribDict({self.technique: AttribDict({"vector": "NEXT TARGET [INFERENCE]"})})})
        _timeless.disengage()
        self.assertEqual(self.kb.injection.data[self.technique].vector, "NEXT TARGET [INFERENCE]")
        self.assertEqual(stale.vector, "AND SLEEP([SLEEPTIME]) [INFERENCE]")

    def test_straggler_rewrite_ignores_a_payload_without_sentinels(self):
        """The rewrite must be a no-op on any ordinary time-based payload."""
        self.assertIsNone(_timeless.restoreClassicValue("id=1 AND SLEEP(5)", "AND SLEEP([SLEEPTIME]) [INFERENCE]"))
        self.assertIsNone(_timeless.restoreClassicValue(None, "AND SLEEP([SLEEPTIME]) [INFERENCE]"))


if __name__ == "__main__":
    unittest.main()
