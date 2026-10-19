#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import arrayizeValue
from lib.core.common import getSQLSnippet
from lib.core.common import isListLike
from lib.core.common import isNoneValue
from lib.core.common import isStackingAvailable
from lib.core.common import unArrayizeValue
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.exception import SqlmapNoneDataException
from lib.core.settings import AUDIT_MAX_ROWS
from lib.utils.safe2bin import safecharencode
from lib.request import inject
from thirdparty import six


class Audit(object):
    # Each snippet returns (audit_key, audit_value). Values are tagged N (SQL NULL) or V<text>
    # so extraction's normal NULL/empty-string handling cannot silently change their meaning.
    dbms = None
    queries = ()
    flags = {}

    def _auditFetch(self, snippet):
        # Extraction locates fields and FROM clauses on one line.
        query = getSQLSnippet(self.dbms, snippet, LIMIT=str(AUDIT_MAX_ROWS)).replace("\r", " ").replace("\n", " ")
        try:
            values = inject.getValue(query, fromUser=True, batch=True, safeCharEncode=False)
        except SqlmapNoneDataException:
            values = None
        if isNoneValue(values):
            # Extraction can return None for both zero rows and a failed query.
            # Confirm emptiness rather than inferring a database error from it.
            countQuery = "SELECT COUNT(*) FROM (%s) audit_count" % query.rsplit(" ORDER BY ", 1)[0]
            try:
                count = inject.getValue(countQuery, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)
            except SqlmapNoneDataException:
                return None
            return {} if getUnicode(unArrayizeValue(count)) == "0" else None
        if isListLike(values) and len(values) == 2 and not any(isListLike(_) for _ in values):
            values = [values]
        facts = {}
        for row in arrayizeValue(values):
            if not isListLike(row) or len(row) != 2:
                return None
            key, value = row
            if isNoneValue(key) or not isinstance(value, six.string_types):
                return None
            if value == "N":
                value = None
            elif value.startswith("V"):
                value = value[1:]
            else:
                return None
            # DBMS CHAR expressions can pad the keys; preserve value whitespace.
            facts[getUnicode(key).rstrip(" ")] = value
        return facts

    def failure(self, scope, groups):
        return "%s: retrieval failed" % scope

    def _auditCanExecute(self):
        # Use known execution routes; audit must not probe takeover gadgets.
        return bool(conf.direct or isStackingAvailable() or kb.get("gadget"))

    def explain(self, groups):
        return []

    def getAudit(self):
        if kb.data.cachedAudit:
            return kb.data.cachedAudit
        logger.info("fetching security configuration and session capabilities")
        groups = {}
        result = []
        for scope, snippets in self.queries:
            facts = None
            for snippet in snippets:
                facts = self._auditFetch(snippet)
                if facts is not None:
                    break
            groups[scope] = facts
            if facts is None:
                result.append(self.failure(scope, groups))
                continue
            if not facts:
                result.append("%s: no entries" % scope)
            for key in sorted(facts):
                if facts[key] is None:
                    value = "<NULL>"
                elif facts[key] == "":
                    value = "<empty>"
                else:
                    value = facts[key]
                    if key in self.flags:
                        if value.lower() in ("1", "on", "true", "yes"):
                            value = self.flags[key][0]
                        elif value.lower() in ("0", "off", "false", "no"):
                            value = self.flags[key][1]
                result.append("%s / %s: %s" % (scope, key, value))
        result.extend(self.explain(groups))
        result = [safecharencode(_) for _ in result]
        kb.data.cachedAudit = result
        return result
