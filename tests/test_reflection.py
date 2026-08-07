#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Adversarial coverage for reflection removal.

Two independent mechanisms exist and the non-SQL engines rely on BOTH:

  lib.core.common.removeReflectiveValues  - the scan-wide heuristic. Powerful (it reassembles a payload
                                            that the page broke apart) but it has global state and
                                            SWITCHES ITSELF OFF: after REFLECTIVE_MISS_THRESHOLD misses,
                                            after a regex timeout, and during heuristic mode.
  lib.utils.nonsql.stripReflection        - a plain deterministic removal with no global state, added
                                            precisely because a detection guard must not stop guarding
                                            halfway through a scan.

The tests below pin the behaviour of each, and - more importantly - pin the blind spots of the first one,
so nobody builds another guard on it without knowing where it does nothing.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import removeReflectiveValues
from lib.core.data import kb
from lib.core.settings import REFLECTED_VALUE_MARKER
from lib.core.settings import REFLECTIVE_MISS_THRESHOLD
from lib.utils.nonsql import stripReflection

PAYLOAD = u"x') or true() or ('"


def _reset():
    kb.reflectiveMechanism = True
    kb.heuristicMode = False
    kb.reflectiveCounters = {"HIT": 0, "MISS": 0}


def _removed(content, payload):
    out = removeReflectiveValues(content, payload, suppressWarning=True)
    return out != content and REFLECTED_VALUE_MARKER in (out or "")


class RemoveReflectiveValuesTest(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_plain_reflection_is_removed(self):
        self.assertTrue(_removed(u"you searched for: %s" % PAYLOAD, PAYLOAD))

    def test_reflection_survives_case_change(self):
        self.assertTrue(_removed(u"YOU SEARCHED FOR: %s" % PAYLOAD.upper(), PAYLOAD))

    def test_reflection_split_by_markup_is_removed(self):
        """The heuristic's real strength: it reassembles a payload the page broke apart."""
        self.assertTrue(_removed(u"search: x') or <b>true()</b> or ('", PAYLOAD))

    def test_html_encoded_reflection_is_removed(self):
        self.assertTrue(_removed(u"you searched for: x&#39;) or true() or (&#39;", PAYLOAD))

    def test_absent_payload_leaves_content_untouched(self):
        content = u"nothing to see here"
        self.assertEqual(removeReflectiveValues(content, PAYLOAD, suppressWarning=True), content)

    def test_empty_inputs_are_safe(self):
        self.assertEqual(removeReflectiveValues(None, PAYLOAD), None)
        self.assertEqual(removeReflectiveValues(u"abc", None), u"abc")
        self.assertEqual(removeReflectiveValues(u"", u""), u"")

    def test_word_only_payload_cannot_explode_the_page(self):
        """A payload of pure word characters yields an empty needle; replacing on it would insert the
        marker between every character."""
        out = removeReflectiveValues(u"aaa bbb aaa", u"aaa", suppressWarning=True)
        self.assertNotIn("%s%s" % (REFLECTED_VALUE_MARKER, REFLECTED_VALUE_MARKER), out or "")


class RemoveReflectiveValuesBlindSpotTest(unittest.TestCase):
    """These document where the scan-wide heuristic does NOTHING. They are the reason a second,
    deterministic guard exists - not bugs to be 'fixed' here."""

    def setUp(self):
        _reset()

    def test_blind_spot_purely_alphanumeric_payload(self):
        """filterStringValue() leaves such a payload unchanged, so the whole routine short-circuits."""
        self.assertFalse(_removed(u"you searched for: abcdefghij", u"abcdefghij"))

    def test_blind_spot_bytes_content(self):
        """It requires text. A byte string is returned untouched - identical behaviour on py2 and py3,
        and the reason every caller must hand it a decoded page."""
        self.assertFalse(_removed(b"you searched for: x", u"x"))

    def test_blind_spot_disabled_mechanism(self):
        """It disables itself on a regex timeout and after REFLECTIVE_MISS_THRESHOLD misses."""
        kb.reflectiveMechanism = False
        self.assertFalse(_removed(u"you searched for: %s" % PAYLOAD, PAYLOAD))

    def test_blind_spot_heuristic_mode(self):
        kb.heuristicMode = True
        self.assertFalse(_removed("you searched for: %s" % PAYLOAD, PAYLOAD))

    def test_miss_threshold_is_finite(self):
        """A guard built only on this stops guarding after this many non-reflective responses."""
        self.assertTrue(0 < REFLECTIVE_MISS_THRESHOLD < 1000)


class StripReflectionTest(unittest.TestCase):
    """The deterministic guard: no global state, no timeout, no self-disabling."""

    def setUp(self):
        _reset()

    def test_removes_the_payload(self):
        out = stripReflection(u"you searched for: %s" % PAYLOAD, PAYLOAD)
        self.assertNotIn(PAYLOAD, out)
        self.assertIn(REFLECTED_VALUE_MARKER, out)

    def test_removes_the_url_encoded_form(self):
        out = stripReflection(u"you searched for: x%27%29%20or%20true%28%29", u"x') or true()")
        self.assertIn(REFLECTED_VALUE_MARKER, out)

    def test_two_different_payloads_collapse_to_the_same_page(self):
        """This is the whole point: a pure echo endpoint must stop looking like a boolean oracle."""
        true_page = stripReflection(u"you searched for: x') or true() or ('", u"x') or true() or ('")
        false_page = stripReflection(u"you searched for: x') and false() and ('", u"x') and false() and ('")
        self.assertEqual(true_page, false_page)

    def test_a_real_differential_is_preserved(self):
        """A genuine oracle differs in the APPLICATION's output, not in the echoed payload, so stripping
        must not erase it."""
        true_page = stripReflection(u"results: luther, fluffy, wu [%s]" % PAYLOAD, PAYLOAD)
        false_page = stripReflection(u"results: none [%s]" % PAYLOAD, PAYLOAD)
        self.assertNotEqual(true_page, false_page)

    def test_does_not_depend_on_global_state(self):
        kb.reflectiveMechanism = False
        kb.heuristicMode = True
        kb.reflectiveCounters = {"HIT": 0, "MISS": REFLECTIVE_MISS_THRESHOLD * 10}
        self.assertIn(REFLECTED_VALUE_MARKER, stripReflection(u"echo: %s" % PAYLOAD, PAYLOAD))

    def test_covers_the_alphanumeric_blind_spot(self):
        self.assertIn(REFLECTED_VALUE_MARKER, stripReflection(u"you searched for: abcdefghij", u"abcdefghij"))

    def test_empty_and_missing_inputs_are_safe(self):
        self.assertEqual(stripReflection(None, PAYLOAD), None)
        self.assertEqual(stripReflection(u"abc", None), u"abc")
        self.assertEqual(stripReflection(u"abc", u""), u"abc")
        self.assertEqual(stripReflection(u"", PAYLOAD), u"")

    def test_absent_payload_leaves_content_identical(self):
        content = u"nothing to see here"
        self.assertEqual(stripReflection(content, PAYLOAD), content)

    def test_every_occurrence_is_removed(self):
        out = stripReflection(u"%s middle %s" % (PAYLOAD, PAYLOAD), PAYLOAD)
        self.assertNotIn(PAYLOAD, out)
        self.assertEqual(out.count(REFLECTED_VALUE_MARKER), 2)


class EnginesUseBothGuardsTest(unittest.TestCase):
    """Pins the wiring. A guard that only one engine applies is how this class of false positive spread
    across three shipped engines unnoticed."""

    def _source(self, *parts):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", *parts)) as f:
            return f.read()

    def test_reflective_engines_apply_both(self):
        for engine in ("xpath", "ldap", "nosql"):
            source = self._source("lib", "techniques", engine, "inject.py")
            self.assertIn("removeReflectiveValues", source, engine)
            self.assertIn("stripReflection", source, engine)

    def test_xslt_proves_evaluation_instead(self):
        """--xslt needs no reflection filter: its sentinel only exists once concat() has run, so an echo
        can never satisfy it. That is the stronger design."""
        source = self._source("lib", "techniques", "xslt", "inject.py")
        self.assertIn("def _captured", source)
        self.assertIn("reflected verbatim", source)


if __name__ == "__main__":
    unittest.main()
