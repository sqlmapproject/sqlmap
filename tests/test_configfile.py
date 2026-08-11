#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline tests for the '-c' configuration-file contract.

configFileParser() walks optDict and reads an option only from the section named after the family that
declares it, so an option is silently dropped - a debug line, nothing else - when the shipped template
and optDict disagree about either its NAME or its SECTION. Both halves of that contract are pinned here
because both had already drifted: three real switches were missing from optDict entirely, the
[Brute force] section could never match the "Brute" family, 'sessionFile' sat under [General] while it
is declared under Target, and two options outlived the switches they configured.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.optiondict import optDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "sqlmap.conf")

_SECTION_REGEX = re.compile(r"^\[(?P<name>.+)\]\s*$")
_OPTION_REGEX = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9_]*)\s*=")


def _configOptions():
    """Every (section, option) pair the shipped template declares, in file order."""

    retVal, section = [], None

    with open(CONFIG) as f:
        for line in f:
            line = line.strip()
            match = _SECTION_REGEX.match(line)
            if match:
                section = match.group("name")
                continue
            match = _OPTION_REGEX.match(line)
            if match:
                retVal.append((section, match.group("name")))

    return retVal


def _sources():
    retVal = []

    for root in ("lib", "plugins"):
        for base, _, files in os.walk(os.path.join(ROOT, root)):
            for name in files:
                if name.endswith(".py"):
                    with open(os.path.join(base, name)) as f:
                        retVal.append(f.read())

    return "\n".join(retVal)


class TestConfigFileContract(unittest.TestCase):
    def test_template_is_not_empty(self):
        self.assertGreater(len(_configOptions()), 100)

    def test_every_option_is_readable_from_its_section(self):
        """The actual lookup configFileProxy() performs: optDict[section][option]."""

        unreadable = ["[%s] %s" % (section, option) for section, option in _configOptions()
                      if option not in optDict.get(section, {})]
        self.assertEqual(unreadable, [], "silently ignored when set via '-c': %s" % ", ".join(unreadable))

    def test_every_section_names_a_family(self):
        sections = set(section for section, _ in _configOptions())
        self.assertEqual(sorted(sections - set(optDict)), [])

    def test_no_option_outlives_its_switch(self):
        """An option nothing reads any more is worse than absent: it reads as supported and does
        nothing. Consumption is either a 'conf.<name>' reference or a lookup by name (the API and the
        library facade address options as strings)."""

        sources = _sources()
        orphans = sorted(set(option for _, option in _configOptions()
                             if not re.search(r"\bconf\.%s\b" % option, sources) and '"%s"' % option not in sources))
        self.assertEqual(orphans, [], "configure nothing: %s" % ", ".join(orphans))


class TestConfigFileRoundTrip(unittest.TestCase):
    """'--save' writes through the same optDict families, and the library facade serializes its kwargs
    that way before handing them over as '-c'. So a config sqlmap writes must be one sqlmap can read."""

    def test_saved_config_reads_back(self):
        import tempfile

        from lib.core.common import saveConfig
        from lib.core.data import conf
        from lib.parse.configfile import configFileParser

        handle, path = tempfile.mkstemp(suffix=".ini")
        os.close(handle)

        # `conf` is the process-wide singleton every other test file shares, so this one saves and
        # restores the WHOLE of it. Clearing it (or leaving a key behind) is not a local mistake: an
        # emptied conf makes `conf.get("direct")` answer for the rest of the run, which silently turns
        # urlencode() into the identity function in test files that run later.
        saved = dict(conf)

        try:
            conf.url = "http://127.0.0.1:1/?id=1"
            conf.commonTables = True
            conf.tablePrefix = "zzz"
            saveConfig(conf, path)

            conf.url, conf.commonTables, conf.tablePrefix = None, False, "overwritten"
            configFileParser(path)

            self.assertEqual(conf.url, "http://127.0.0.1:1/?id=1")
            self.assertTrue(conf.commonTables)
            self.assertEqual(conf.tablePrefix, "zzz")
        finally:
            conf.clear()
            conf.update(saved)
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
