#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Parser-introspection helpers in lib/utils/gui.py. The GUI itself needs a live
display (Tk), so it is excluded from the smoke test and never imported there;
these module-level helpers, however, are pure and work on argparse/optparse
parser+option objects. We exercise BOTH backends (argparse natively, optparse
via a lightweight stand-in) so the compatibility branches are walked. Importing
the module also covers its (otherwise-uncovered) top-level definitions.
"""

import argparse
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.utils import gui


class _OptparseLikeOption(object):
    """Minimal optparse.Option stand-in (drives the non-argparse branches)."""
    def __init__(self, short, long_, dest, help_, type_=None, takes=True):
        self._short_opts = [short] if short else []
        self._long_opts = [long_] if long_ else []
        self.dest = dest
        self.help = help_
        self.type = type_
        self._takes = takes

    def takes_value(self):
        return self._takes


class _OptparseLikeGroup(object):
    def __init__(self, title, description, options):
        self.title = title
        self.description = description
        self.option_list = options

    def get_description(self):
        return self.description


def _build_argparse():
    p = argparse.ArgumentParser()
    g = p.add_argument_group("Target", "options for the target")
    g.add_argument("-u", "--url", dest="url", help="target url")
    g.add_argument("--level", dest="level", type=int, help="level", choices=[1, 2, 3])
    g.add_argument("--flag", dest="flag", action="store_true", help="a boolean")
    return p, g


class TestArgparseBackend(unittest.TestCase):
    def setUp(self):
        self.parser, self.group = _build_argparse()

    def test_parser_groups_found(self):
        groups = gui._parserGroups(self.parser)
        titles = [gui._groupTitle(g) for g in groups]
        self.assertIn("Target", titles)

    def test_group_options_and_metadata(self):
        opts = gui._groupOptions(self.group)
        self.assertTrue(opts)
        self.assertEqual(gui._groupDescription(self.group), "options for the target")

    def test_opt_accessors(self):
        opts = gui._groupOptions(self.group)
        by_dest = dict((gui._optDest(o), o) for o in opts)
        url = by_dest["url"]
        self.assertIn("--url", gui._optStrings(url))
        self.assertEqual(gui._optHelp(url), "target url")
        self.assertTrue(gui._optTakesValue(url))
        self.assertEqual(gui._optValueType(url), "string")
        self.assertIn("--url", gui._optionLabel(url))

    def test_int_type_and_choices(self):
        opts = gui._groupOptions(self.group)
        by_dest = dict((gui._optDest(o), o) for o in opts)
        level = by_dest["level"]
        self.assertEqual(gui._optValueType(level), "int")
        self.assertEqual(gui._optChoices(level), [1, 2, 3])

    def test_store_true_takes_no_value(self):
        opts = gui._groupOptions(self.group)
        by_dest = dict((gui._optDest(o), o) for o in opts)
        self.assertFalse(gui._optTakesValue(by_dest["flag"]))


class TestOptparseBackend(unittest.TestCase):
    def setUp(self):
        self.opt = _OptparseLikeOption("-u", "--url", "url", "target url", type_="string")
        self.intopt = _OptparseLikeOption(None, "--level", "level", "level", type_="int")
        self.boolopt = _OptparseLikeOption(None, "--flag", "flag", "flag", takes=False)
        self.group = _OptparseLikeGroup("Target", "target opts", [self.opt, self.intopt, self.boolopt])

    def test_opt_strings_from_short_long(self):
        self.assertEqual(gui._optStrings(self.opt), ["-u", "--url"])

    def test_value_type_and_takes(self):
        self.assertEqual(gui._optValueType(self.intopt), "int")
        self.assertTrue(gui._optTakesValue(self.opt))
        self.assertFalse(gui._optTakesValue(self.boolopt))

    def test_group_description_via_method(self):
        self.assertEqual(gui._groupDescription(self.group), "target opts")
        self.assertEqual(gui._groupOptions(self.group), [self.opt, self.intopt, self.boolopt])


if __name__ == "__main__":
    unittest.main()
