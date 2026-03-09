#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

AI-powered tamper script recommendation and dynamic evasion.
Analyzes target responses to suggest and auto-apply optimal
tamper scripts for WAF/IPS bypass.
"""

import os
import re

from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger


class AITamperAdvisor(object):
    """
    Recommends tamper scripts based on detected WAF/IPS behavior
    and target DBMS characteristics.
    """

    # Tamper script categorization by purpose
    TAMPER_CATEGORIES = {
        "encoding": [
            "charencode", "chardoubleencode", "charunicodeencode",
            "charunicodeescape", "base64encode", "hexentities",
            "decentities", "htmlencode", "overlongutf8", "overlongutf8more",
        ],
        "space_bypass": [
            "space2comment", "space2dash", "space2hash",
            "space2morecomment", "space2morehash", "space2mssqlblank",
            "space2mssqlhash", "space2mysqlblank", "space2mysqldash",
            "space2plus", "space2randomblank", "multiplespaces",
        ],
        "keyword_bypass": [
            "between", "equaltolike", "greatest", "least",
            "randomcase", "randomcomments", "versionedkeywords",
            "versionedmorekeywords", "halfversionedmorekeywords",
            "symboliclogical", "commentbeforeparentheses",
        ],
        "function_bypass": [
            "concat2concatws", "ifnull2casewhenisnull",
            "ifnull2ifisnull", "if2case", "substring2leftright",
            "sleep2getlock", "ord2ascii", "plus2concat", "plus2fnconcat",
        ],
        "union_bypass": [
            "0eunion", "dunion", "misunion", "unionalltounion",
        ],
        "misc_bypass": [
            "apostrophemask", "apostrophenullencode", "appendnullbyte",
            "binary", "bluecoat", "escapequotes", "luanginx",
            "modsecurityversioned", "modsecurityzeroversioned",
            "percentage", "schemasplit", "scientific",
            "sp_password", "unmagicquotes", "uppercase", "lowercase",
            "varnish", "xforwardedfor", "informationschemacomment",
        ],
    }

    # DBMS-specific tamper effectiveness
    DBMS_TAMPER_AFFINITY = {
        "MySQL": {
            "high": [
                "space2comment", "between", "randomcase", "charencode",
                "versionedkeywords", "versionedmorekeywords",
                "halfversionedmorekeywords", "space2mysqlblank",
                "space2mysqldash", "concat2concatws", "ifnull2ifisnull",
                "percentage", "modsecurityversioned",
            ],
            "medium": [
                "space2hash", "space2morehash", "randomcomments",
                "commentbeforeparentheses", "equaltolike", "greatest",
            ],
            "low": [
                "space2mssqlblank", "space2mssqlhash",
            ],
        },
        "Microsoft SQL Server": {
            "high": [
                "space2comment", "between", "randomcase", "charencode",
                "space2mssqlblank", "space2mssqlhash", "sp_password",
                "plus2concat", "plus2fnconcat",
            ],
            "medium": [
                "percentage", "randomcomments", "commentbeforeparentheses",
                "greatest", "equaltolike",
            ],
            "low": [
                "space2mysqlblank", "versionedkeywords",
            ],
        },
        "PostgreSQL": {
            "high": [
                "space2comment", "between", "randomcase", "charencode",
                "greatest", "least", "substring2leftright",
            ],
            "medium": [
                "charunicodeencode", "randomcomments", "percentage",
                "commentbeforeparentheses",
            ],
            "low": [
                "space2mssqlblank", "versionedkeywords",
            ],
        },
        "Oracle": {
            "high": [
                "space2comment", "between", "randomcase", "charencode",
                "greatest", "least",
            ],
            "medium": [
                "randomcomments", "commentbeforeparentheses",
                "charunicodeencode",
            ],
            "low": [
                "space2mssqlblank", "versionedkeywords",
            ],
        },
        "SQLite": {
            "high": [
                "space2comment", "randomcase", "charencode",
            ],
            "medium": [
                "between", "randomcomments", "percentage",
            ],
            "low": [
                "space2mssqlblank", "versionedkeywords",
            ],
        },
    }

    def __init__(self):
        self._testedTampers = {}
        self._effectiveTampers = []
        self._availableTampers = set()
        self._loadAvailableTampers()

    def _loadAvailableTampers(self):
        """Load list of available tamper scripts from the tamper directory."""
        tamperDir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "tamper")

        if os.path.isdir(tamperDir):
            for filename in os.listdir(tamperDir):
                if filename.endswith(".py") and not filename.startswith("__"):
                    self._availableTampers.add(filename[:-3])

    def recommendTampers(self, wafName=None, dbms=None, maxResults=5):
        """
        Recommend tamper scripts based on detected WAF and DBMS.
        Returns ordered list of (tamper_name, reason, priority) tuples.
        """

        recommendations = []
        seen = set()

        # WAF-specific recommendations (handled by engine.py WAFAnalyzer)
        # Here we focus on DBMS-specific and general recommendations

        if dbms:
            dbmsAffinity = self.DBMS_TAMPER_AFFINITY.get(dbms, {})
            for tamper in dbmsAffinity.get("high", []):
                if tamper in self._availableTampers and tamper not in seen:
                    recommendations.append((tamper, "High effectiveness for %s" % dbms, 3))
                    seen.add(tamper)

            for tamper in dbmsAffinity.get("medium", []):
                if tamper in self._availableTampers and tamper not in seen:
                    recommendations.append((tamper, "Medium effectiveness for %s" % dbms, 2))
                    seen.add(tamper)

        # General high-value tampers
        generalTampers = [
            ("space2comment", "Universal space bypass", 2),
            ("between", "Replaces > with BETWEEN - evades many filters", 2),
            ("randomcase", "Randomizes SQL keyword casing", 2),
            ("charencode", "URL-encodes characters", 1),
            ("percentage", "ASP percentage encoding bypass", 1),
        ]

        for tamper, reason, priority in generalTampers:
            if tamper in self._availableTampers and tamper not in seen:
                recommendations.append((tamper, reason, priority))
                seen.add(tamper)

        # Sort by priority (highest first), then alphabetically
        recommendations.sort(key=lambda x: (-x[2], x[0]))
        return recommendations[:maxResults]

    def recordTamperResult(self, tamperName, effective):
        """Record whether a tamper script was effective."""
        self._testedTampers[tamperName] = effective
        if effective:
            self._effectiveTampers.append(tamperName)

    def getEffectiveTampers(self):
        """Return list of tamper scripts that proved effective."""
        return list(self._effectiveTampers)

    def getTamperCombination(self, wafName=None, dbms=None):
        """
        Suggest a combination of tamper scripts that work well together.
        Returns comma-separated tamper string ready for --tamper option.
        """

        combo = []
        seen = set()

        # One space bypass
        spaceTampers = self.TAMPER_CATEGORIES["space_bypass"]
        for t in spaceTampers:
            if t in self._availableTampers:
                combo.append(t)
                seen.add(t)
                break

        # One keyword bypass
        kwTampers = self.TAMPER_CATEGORIES["keyword_bypass"]
        for t in kwTampers:
            if t in self._availableTampers and t not in seen:
                combo.append(t)
                seen.add(t)
                break

        # One encoding
        encTampers = self.TAMPER_CATEGORIES["encoding"]
        for t in encTampers:
            if t in self._availableTampers and t not in seen:
                combo.append(t)
                seen.add(t)
                break

        return ",".join(combo) if combo else None


def getAITamperAdvisor():
    """Get a tamper advisor instance."""
    if not hasattr(kb, "_aiTamperAdvisor") or kb._aiTamperAdvisor is None:
        kb._aiTamperAdvisor = AITamperAdvisor()
    return kb._aiTamperAdvisor
