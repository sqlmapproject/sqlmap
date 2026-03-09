#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

AI-powered scan report generation with intelligent risk assessment,
vulnerability scoring, and remediation recommendations.
"""

import time

from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD


class AIVulnerabilityScorer(object):
    """
    Calculates CVSS-like vulnerability scores for discovered SQL injections
    based on injection type, DBMS, access level, and exploitability.
    """

    # Base scores by technique type
    TECHNIQUE_BASE_SCORES = {
        PAYLOAD.TECHNIQUE.BOOLEAN: 6.5,
        PAYLOAD.TECHNIQUE.ERROR: 7.0,
        PAYLOAD.TECHNIQUE.UNION: 8.0,
        PAYLOAD.TECHNIQUE.STACKED: 9.0,
        PAYLOAD.TECHNIQUE.TIME: 5.5,
        PAYLOAD.TECHNIQUE.QUERY: 7.5,
    }

    # DBMS risk multipliers
    DBMS_RISK_MULTIPLIER = {
        DBMS.MYSQL: 1.0,
        DBMS.PGSQL: 1.05,
        DBMS.MSSQL: 1.15,
        DBMS.ORACLE: 1.1,
        DBMS.SQLITE: 0.85,
    }

    SEVERITY_LEVELS = {
        (0.0, 3.9): ("LOW", "\033[32m"),
        (4.0, 6.9): ("MEDIUM", "\033[33m"),
        (7.0, 8.9): ("HIGH", "\033[91m"),
        (9.0, 10.0): ("CRITICAL", "\033[31m"),
    }

    def scoreInjection(self, injection):
        """
        Score a single injection point.
        Returns (score, severity, details) tuple.
        """

        if not injection or not injection.data:
            return 0.0, "NONE", {}

        maxScore = 0.0
        details = {
            "techniques": [],
            "exploitability": 0.0,
            "impact": 0.0,
        }

        for stype, sdata in injection.data.items():
            baseScore = self.TECHNIQUE_BASE_SCORES.get(stype, 5.0)

            # Apply DBMS multiplier
            dbms = injection.dbms
            if dbms:
                if isinstance(dbms, list):
                    dbms = dbms[0] if dbms else None
                multiplier = self.DBMS_RISK_MULTIPLIER.get(dbms, 1.0)
                baseScore *= multiplier

            # Stacked queries can lead to full compromise
            if stype == PAYLOAD.TECHNIQUE.STACKED:
                baseScore = min(10.0, baseScore * 1.2)

            # UNION allows direct data extraction
            if stype == PAYLOAD.TECHNIQUE.UNION:
                baseScore = min(10.0, baseScore * 1.1)

            techName = PAYLOAD.SQLINJECTION.get(stype, "Unknown")
            details["techniques"].append({
                "type": techName,
                "score": round(baseScore, 1),
                "title": sdata.title,
            })

            maxScore = max(maxScore, baseScore)

        maxScore = min(10.0, maxScore)
        severity = self._getSeverity(maxScore)

        details["exploitability"] = min(10.0, maxScore * 0.9)
        details["impact"] = min(10.0, maxScore * 0.85)

        return round(maxScore, 1), severity, details

    def _getSeverity(self, score):
        """Get severity label for a given score."""
        for (low, high), (label, _) in self.SEVERITY_LEVELS.items():
            if low <= score <= high:
                return label
        return "UNKNOWN"

    def getSeverityColor(self, score):
        """Get ANSI color code for a severity score."""
        for (low, high), (_, color) in self.SEVERITY_LEVELS.items():
            if low <= score <= high:
                return color
        return "\033[0m"


class AIReportGenerator(object):
    """
    Generates comprehensive AI-powered scan reports with:
    - Vulnerability scoring and risk assessment
    - Attack narrative (how the injection was found)
    - Remediation recommendations
    - Executive summary
    """

    REMEDIATION_ADVICE = {
        PAYLOAD.TECHNIQUE.BOOLEAN: [
            "Use parameterized queries (prepared statements) for all database operations",
            "Implement input validation with strict type checking",
            "Apply the principle of least privilege to database accounts",
        ],
        PAYLOAD.TECHNIQUE.ERROR: [
            "Disable detailed error messages in production environments",
            "Use parameterized queries to prevent SQL injection",
            "Implement custom error handlers that log errors without exposing them",
        ],
        PAYLOAD.TECHNIQUE.UNION: [
            "Use parameterized queries - UNION-based injection indicates direct query manipulation",
            "Restrict database user permissions to required tables only",
            "Implement Web Application Firewall rules for UNION-based attacks",
        ],
        PAYLOAD.TECHNIQUE.STACKED: [
            "CRITICAL: Stacked queries allow arbitrary SQL execution",
            "Immediately switch to parameterized queries",
            "Restrict database account to SELECT-only where possible",
            "Implement query whitelisting at the database proxy level",
        ],
        PAYLOAD.TECHNIQUE.TIME: [
            "Use parameterized queries to prevent time-based blind injection",
            "Implement request timeout limits at the application level",
            "Monitor for unusual query execution times",
        ],
        PAYLOAD.TECHNIQUE.QUERY: [
            "Use parameterized queries for all database interactions",
            "Implement strict input validation and output encoding",
        ],
    }

    def __init__(self):
        self.scorer = AIVulnerabilityScorer()

    def generateReport(self, injections, scanStats=None):
        """Generate a complete AI analysis report."""

        report = []
        report.append("")
        report.append("\033[1m" + "=" * 60 + "\033[0m")
        report.append("\033[1m[AI] INTELLIGENT VULNERABILITY ANALYSIS REPORT\033[0m")
        report.append("\033[1m" + "=" * 60 + "\033[0m")
        report.append("")

        if not injections:
            report.append("No SQL injection vulnerabilities were identified.")
            report.append("")
            report.append("Recommendations:")
            report.append("  - Increase test level (--level=5) and risk (--risk=3)")
            report.append("  - Try different tamper scripts if WAF is present")
            report.append("  - Verify the target URL and parameters are correct")
            return "\n".join(report)

        # Executive Summary
        report.append("\033[1m[*] EXECUTIVE SUMMARY\033[0m")
        report.append("-" * 40)

        totalVulns = len(injections)
        maxScore = 0
        maxSeverity = "LOW"

        for inj in injections:
            score, severity, _ = self.scorer.scoreInjection(inj)
            if score > maxScore:
                maxScore = score
                maxSeverity = severity

        color = self.scorer.getSeverityColor(maxScore)
        report.append("Vulnerabilities found: %d" % totalVulns)
        report.append("Highest risk score: %s%.1f/10.0 (%s)\033[0m" % (color, maxScore, maxSeverity))
        report.append("")

        # Detailed findings
        report.append("\033[1m[*] DETAILED FINDINGS\033[0m")
        report.append("-" * 40)

        for i, inj in enumerate(injections, 1):
            score, severity, details = self.scorer.scoreInjection(inj)
            color = self.scorer.getSeverityColor(score)

            report.append("")
            report.append("\033[1mFinding #%d\033[0m" % i)
            report.append("  Parameter: %s (%s)" % (inj.parameter, inj.place))

            if inj.dbms:
                dbmsStr = inj.dbms if isinstance(inj.dbms, str) else "/".join(inj.dbms) if inj.dbms else "Unknown"
                report.append("  DBMS: %s" % dbmsStr)

            report.append("  Risk Score: %s%.1f/10.0 (%s)\033[0m" % (color, score, severity))
            report.append("")

            report.append("  Techniques:")
            for tech in details["techniques"]:
                report.append("    - %s (score: %.1f)" % (tech["type"], tech["score"]))
                report.append("      Payload: %s" % tech["title"])

            # Remediation
            report.append("")
            report.append("  \033[1mRemediation:\033[0m")
            remediationSeen = set()
            for stype in inj.data:
                for advice in self.REMEDIATION_ADVICE.get(stype, []):
                    if advice not in remediationSeen:
                        report.append("    - %s" % advice)
                        remediationSeen.add(advice)

        # Scan statistics
        if scanStats:
            report.append("")
            report.append("\033[1m[*] SCAN STATISTICS\033[0m")
            report.append("-" * 40)
            report.append(scanStats)

        # General recommendations
        report.append("")
        report.append("\033[1m[*] GENERAL RECOMMENDATIONS\033[0m")
        report.append("-" * 40)
        report.append("  1. Implement parameterized queries across all database interactions")
        report.append("  2. Apply input validation at all entry points")
        report.append("  3. Use the principle of least privilege for database accounts")
        report.append("  4. Deploy a Web Application Firewall (WAF) as defense-in-depth")
        report.append("  5. Regularly perform security testing and code reviews")
        report.append("  6. Keep all frameworks and libraries updated")
        report.append("")
        report.append("\033[1m" + "=" * 60 + "\033[0m")

        return "\n".join(report)


def generateAIReport(injections, scanStats=None):
    """Convenience function to generate an AI report."""
    generator = AIReportGenerator()
    return generator.generateReport(injections, scanStats)
