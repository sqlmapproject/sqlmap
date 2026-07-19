#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Crawler result normalization (lib/utils/crawler.py normalizeCrawlingResults).

--crawl can surface thousands of near-identical URLs; normalization keeps one
representative per distinct endpoint+parameter shape so the scan is not flooded
with value-only variants. The key must span the full path: collapsing on the
last path segment alone silently drops distinct endpoints that share an action
name (e.g. /users/edit vs /products/edit), losing real attack surface.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.utils.crawler import normalizeCrawlingResults


def _t(url, data=None):
    # kb.targets tuple shape: (url, method, data, ...)
    return (url, None, data, None, None)


class TestNormalizeCrawlingResults(unittest.TestCase):
    def _urls(self, targets):
        return [t[0] for t in normalizeCrawlingResults(targets)]

    def test_value_only_variants_collapse(self):
        kept = self._urls([_t("http://h/item?id=1"), _t("http://h/item?id=2"), _t("http://h/item?id=3")])
        self.assertEqual(kept, ["http://h/item?id=1"])

    def test_distinct_endpoints_sharing_action_are_kept(self):
        # the regression: /users/edit and /products/edit must not collapse on the shared last segment
        kept = self._urls([_t("http://h/users/edit?id=1"),
                           _t("http://h/products/edit?id=1"),
                           _t("http://h/orders/edit?id=1"),
                           _t("http://h/users/edit?id=2")])
        self.assertEqual(set(kept), {"http://h/users/edit?id=1",
                                     "http://h/products/edit?id=1",
                                     "http://h/orders/edit?id=1"})

    def test_different_parameter_names_are_kept(self):
        kept = self._urls([_t("http://h/p?id=1"), _t("http://h/p?name=x")])
        self.assertEqual(set(kept), {"http://h/p?id=1", "http://h/p?name=x"})

    def test_different_hosts_are_kept(self):
        kept = self._urls([_t("http://a.tld/edit?id=1"), _t("http://b.tld/edit?id=1")])
        self.assertEqual(set(kept), {"http://a.tld/edit?id=1", "http://b.tld/edit?id=1"})

    def test_post_data_folded_into_shape(self):
        # POST body params participate in the shape, and value-only POST variants collapse
        kept = self._urls([_t("http://h/login", "user=a&pass=b"), _t("http://h/login", "user=c&pass=d")])
        self.assertEqual(kept, ["http://h/login"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
