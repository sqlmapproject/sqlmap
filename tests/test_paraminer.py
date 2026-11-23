#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Hidden GET parameter mining (lib/utils/paraminer.py), driven through the real
mineParameters() entry point with a MOCKED HTTP layer.

paraminer has two independent oracles: value reflection, and a behavioral side
effect on the response. The behavioral one is gated on 'floor', the target's own
between-request jitter, measured with a second fetch of the baseline. These tests
pin what happens to that oracle when the jitter probe itself does not come back.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf
from lib.core.enums import PLACE
from lib.utils import paraminer

BASE = "<html><head><title>Index</title></head><body><h1>Welcome</h1><p>Nothing to see here.</p></body></html>"

# the same page plus a debug block: no canary is echoed, so only the behavioral oracle can see it
CHANGED = ("<html><head><title>Index</title></head><body><h1>Welcome</h1><p>Nothing to see here.</p>"
           "<pre>DEBUG TRACE 7731\nquery: SELECT col FROM tbl WHERE id = 1\nrows: 1\nelapsed: 42ms\n"
           "cache: miss\nbackend: pg-04\n</pre></body></html>")


class TestMineParametersJitterProbe(unittest.TestCase):
    def setUp(self):
        self._origGetPage = paraminer.Request.getPage
        self._origGetFileItems = paraminer.getFileItems
        self._origParameters = dict(conf.parameters)
        self._origParamDict = dict(conf.paramDict)
        self._origData, self._origMethod = conf.data, conf.method

        conf.data = None
        conf.method = None
        conf.parameters[PLACE.GET] = "id=1"
        conf.paramDict[PLACE.GET] = {"id": "1"}

        # keep the candidate list to the one name under test instead of all of common-params.txt
        paraminer.getFileItems = staticmethod(lambda path, unique=False: ["debug"])

    def tearDown(self):
        paraminer.Request.getPage = self._origGetPage
        paraminer.getFileItems = self._origGetFileItems
        conf.parameters.clear()
        conf.parameters.update(self._origParameters)
        conf.paramDict.clear()
        conf.paramDict.update(self._origParamDict)
        conf.data, conf.method = self._origData, self._origMethod

    def _patch(self, jitterProbe):
        """Mocks the network. The second request is always the jitter probe (see mineParameters)."""

        calls = []

        def getPage(**kwargs):
            get = kwargs.get("get") or ""
            calls.append(get)

            if len(calls) == 1:                 # baseline
                return BASE, None, 200
            if len(calls) == 2:                 # the jitter probe
                return jitterProbe()
            if "debug=" in get:                 # the hidden parameter changes the response
                return CHANGED, None, 200
            return BASE, None, 200

        paraminer.Request.getPage = staticmethod(getPage)
        return calls

    def test_behavioral_oracle_survives_an_unanswered_jitter_probe(self):
        # a single dropped request must not cost us the parameter: _fetch() swallows the exception
        # and returns an empty page, which is exactly the case 'floor' has to cope with
        def dropped():
            raise Exception("connection reset")

        self._patch(dropped)
        paraminer.mineParameters()

        self.assertIn("debug", conf.paramDict[PLACE.GET],
                      msg="hidden parameter lost because the jitter probe did not come back")
        self.assertEqual(conf.paramDict[PLACE.GET]["debug"], paraminer.PROBE_VALUE)

    def test_behavioral_oracle_survives_an_empty_jitter_probe(self):
        self._patch(lambda: ("", None, 200))
        paraminer.mineParameters()

        self.assertIn("debug", conf.paramDict[PLACE.GET])

    def test_behavioral_oracle_with_a_normal_jitter_probe(self):
        # control: with the jitter probe answered as usual the parameter is found, so the two tests
        # above are about the probe failing and not about the mining itself
        self._patch(lambda: (BASE, None, 200))
        paraminer.mineParameters()

        self.assertIn("debug", conf.paramDict[PLACE.GET])

    def test_a_target_that_ignores_the_candidate_yields_nothing(self):
        # control in the other direction: no behavioral change, so nothing may be added
        def getPage(**kwargs):
            return BASE, None, 200

        paraminer.Request.getPage = staticmethod(getPage)
        paraminer.mineParameters()

        self.assertNotIn("debug", conf.paramDict[PLACE.GET])


if __name__ == "__main__":
    unittest.main(verbosity=2)
