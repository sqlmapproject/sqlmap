#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Contract test: the OpenAPI spec (sqlmapapi.yaml) must stay in lock-step with the
REST API actually served by lib/utils/api.py. The spec is hand-maintained, so it
is the exact thing that silently drifts when an endpoint is added/renamed/retyped.

This walks the live Bottle route table (every @get/@post registers at import time)
and the spec's `paths:` block, and asserts the (method, path) sets are identical
in BOTH directions - no undocumented route, no phantom spec entry - plus that the
spec's advertised version matches the runtime RESTAPI_VERSION.

PyYAML is not bundled (and the suite is stdlib-only / no pip), so the spec is read
with a tiny indentation-aware scanner that only needs the paths + info.version.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

__import__("lib.utils.api")   # registers Bottle routes (side-effect import)
from lib.core.settings import RESTAPI_VERSION
from thirdparty.bottle.bottle import default_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, "sqlmapapi.yaml")

# Bottle-only routes that are not part of the documented public contract
INTERNAL_RULES = ("/error/401",)

HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")


def _normalize_rule(rule):
    # Bottle '<taskid>' / '<filename:path>' -> OpenAPI '{taskid}' / '{filename}'
    return re.sub(r"<([^:>]+)(?::[^>]+)?>", r"{\1}", rule)


def _app_pairs():
    pairs = set()
    for route in default_app().routes:
        rule = _normalize_rule(route.rule)
        if rule in INTERNAL_RULES:
            continue
        pairs.add((route.method.lower(), rule))
    return pairs


def _spec_paths_and_version(text):
    """Returns (set of (method, path), info.version) from the YAML text."""
    pairs = set()
    version = None
    section = None
    current_path = None

    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        top = re.match(r"^(\S[^:]*):", line)        # a column-0 key starts a new top-level section
        if top:
            section = top.group(1)
            current_path = None
            continue

        if section == "info":
            m = re.match(r"^  version:\s*(.+?)\s*$", line)
            if m:
                version = m.group(1).strip().strip('"').strip("'")
        elif section == "paths":
            m = re.match(r"^  (/\S*):\s*$", line)    # 2-space path key
            if m:
                current_path = m.group(1)
                continue
            m = re.match(r"^    (\w+):\s*$", line)    # 4-space method key
            if m and current_path and m.group(1).lower() in HTTP_METHODS:
                pairs.add((m.group(1).lower(), current_path))

    return pairs, version


class TestOpenAPIDrift(unittest.TestCase):
    def setUp(self):
        with open(SPEC) as f:
            self.spec_pairs, self.spec_version = _spec_paths_and_version(f.read())
        self.app_pairs = _app_pairs()

    def test_parsers_found_something(self):
        # guard against a silently-empty parse making the equality checks vacuously pass
        self.assertTrue(len(self.app_pairs) >= 15, self.app_pairs)
        self.assertEqual(len(self.spec_pairs), len(self.app_pairs))

    def test_no_undocumented_endpoint(self):
        missing = self.app_pairs - self.spec_pairs
        self.assertEqual(missing, set(), "served but absent from sqlmapapi.yaml: %s" % sorted(missing))

    def test_no_phantom_spec_entry(self):
        extra = self.spec_pairs - self.app_pairs
        self.assertEqual(extra, set(), "in sqlmapapi.yaml but not served: %s" % sorted(extra))

    def test_version_matches_runtime(self):
        self.assertEqual(self.spec_version, RESTAPI_VERSION, "sqlmapapi.yaml version '%s' != RESTAPI_VERSION '%s'" % (self.spec_version, RESTAPI_VERSION))


if __name__ == "__main__":
    unittest.main()
