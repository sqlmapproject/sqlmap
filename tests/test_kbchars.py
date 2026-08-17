#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Invariants of the random markers in kb.chars (lib/core/option.py).

These markers are drawn at random once per run, so a collision between two of them is a
heisenbug: it corrupts extraction only in the fraction of runs that happen to draw the same
value twice. Both collisions below were observed and are pinned here.

  start/stop                 wrap the delimited output. Equal values make the output ambiguous
                             (a two-row result then carries four identical markers instead of
                             two pairs), so the parsing returns garbage or nothing at all.
  at/space/dollar/hash_      stand in for '@', ' ', '$' and '#' inside a single chained REPLACE()
                             (see the Oracle XMLType vectors in error_based.xml). Two equal
                             markers make _errorReplaceChars() restore whichever character it
                             tries first, so e.g. an '@' in an e-mail column comes back as ' '.

The loop count is what matters: the smaller alphabet collides once every ~512 draws and the
single-letter one every ~5, so a single sample proves nothing.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import kb
from lib.core.option import _setKnowledgeBaseAttributes

ROUNDS = 3000

MARKERS = ("start", "stop", "at", "space", "dollar", "hash_")


class KbCharsDistinctTest(unittest.TestCase):
    """Re-draws the markers many times. kb is global, so it is snapshotted and put back -
    leaking a fresh kb into the rest of the suite is how this bug got noticed in the first place."""

    def setUp(self):
        self._saved = dict(kb)

    def tearDown(self):
        kb.clear()
        kb.update(self._saved)

    def test_markers_never_collide(self):
        for i in range(ROUNDS):
            _setKnowledgeBaseAttributes()
            drawn = [getattr(kb.chars, _) for _ in MARKERS]
            self.assertEqual(len(set(drawn)), len(MARKERS),
                             msg="colliding kb.chars markers on round %d: %s" % (i, dict(zip(MARKERS, drawn))))

    def test_markers_never_contain_each_other(self):
        # whole-string distinctness is not enough: the boundary character wrapping every marker used
        # to be drawn for the inner letters as well, so a start marker could render as 'qzqxq', which
        # carries the perfectly legal replacement marker 'qzq' (and 'qxq') inside it
        for i in range(ROUNDS):
            _setKnowledgeBaseAttributes()
            drawn = [getattr(kb.chars, _) for _ in MARKERS]
            for one in drawn:
                for other in drawn:
                    if one is not other:
                        self.assertNotIn(other, one,
                                         msg="kb.chars marker %r contains %r on round %d" % (one, other, i))

    def test_markers_keep_their_shape(self):
        # the fix must not change the on-the-wire length of a payload
        for _ in range(ROUNDS // 100):
            _setKnowledgeBaseAttributes()
            self.assertEqual(len(kb.chars.start), 5)
            self.assertEqual(len(kb.chars.stop), 5)
            for name in ("at", "space", "dollar", "hash_"):
                self.assertEqual(len(getattr(kb.chars, name)), 3, msg=name)
            self.assertEqual(len(kb.chars.delimiter), 6)

    def test_kb_is_restored(self):
        # guards the snapshot above, so a later failure elsewhere is never blamed on this file
        _setKnowledgeBaseAttributes()
        self.assertNotEqual(dict(kb).get("chars"), self._saved.get("chars"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
