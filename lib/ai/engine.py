#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

AI-powered engine for intelligent SQL injection analysis.
Provides response pattern learning, smart payload prioritization,
WAF fingerprinting, and adaptive attack strategies.
"""

import hashlib
import math
import os
import re
import time

from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.settings import UPPER_RATIO_BOUND


class AIResponseAnalyzer(object):
    """
    Learns patterns from HTTP responses to improve detection accuracy.
    Uses statistical analysis of response characteristics to distinguish
    true/false conditions and identify injection points more efficiently.
    """

    def __init__(self):
        self._responseProfiles = {}
        self._statusCodeDistribution = {}
        self._contentLengthHistory = []
        self._responseTimeHistory = []
        self._errorPatterns = set()
        self._trueConditionSignatures = []
        self._falseConditionSignatures = []
        self._confidenceThreshold = 0.75
        self._learningRate = 0.1
        self._patternWeights = {
            "status_code": 0.20,
            "content_length": 0.25,
            "response_time": 0.15,
            "error_pattern": 0.25,
            "structural": 0.15,
        }

    def analyzeResponse(self, response, statusCode, responseTime=None):
        """
        Analyze an HTTP response and build a feature profile for it.
        Returns a signature dict of extracted features.
        """

        signature = {
            "status_code": statusCode,
            "content_length": len(response) if response else 0,
            "response_time": responseTime or 0,
            "has_error": False,
            "error_type": None,
            "structural_hash": None,
            "tag_count": 0,
            "word_count": 0,
        }

        if response:
            # Structural analysis
            signature["structural_hash"] = self._computeStructuralHash(response)
            signature["tag_count"] = len(re.findall(r"<[^>]+>", response))
            signature["word_count"] = len(response.split())

            # Error pattern detection
            errorPatterns = [
                (r"(?i)sql\s*(syntax|error|exception)", "sql_error"),
                (r"(?i)mysql_fetch|pg_query|ora-\d+", "db_driver_error"),
                (r"(?i)warning\s*:\s*(mysql|pg_|oci|sqlite)", "db_warning"),
                (r"(?i)unclosed\s+quotation|unterminated\s+string", "quote_error"),
                (r"(?i)division\s+by\s+zero|conversion\s+failed", "type_error"),
                (r"(?i)you\s+have\s+an\s+error\s+in\s+your\s+SQL", "mysql_error"),
                (r"(?i)ODBC\s+SQL\s+Server\s+Driver", "mssql_error"),
                (r"(?i)ORA-\d{5}", "oracle_error"),
                (r"(?i)PostgreSQL.*ERROR", "pgsql_error"),
                (r"(?i)Microsoft.*ODBC.*Driver", "odbc_error"),
                (r"(?i)SQLite3?::query", "sqlite_error"),
                (r"(?i)DB2\s+SQL\s+error", "db2_error"),
                (r"(?i)403\s+Forbidden|Access\s+Denied", "waf_block"),
                (r"(?i)406\s+Not\s+Acceptable", "waf_block"),
            ]

            for pattern, errorType in errorPatterns:
                if re.search(pattern, response):
                    signature["has_error"] = True
                    signature["error_type"] = errorType
                    self._errorPatterns.add(errorType)
                    break

        # Track statistics
        self._contentLengthHistory.append(signature["content_length"])
        if responseTime:
            self._responseTimeHistory.append(responseTime)

        statusCode = signature["status_code"]
        self._statusCodeDistribution[statusCode] = self._statusCodeDistribution.get(statusCode, 0) + 1

        return signature

    def learnTrueCondition(self, signature):
        """Record a response signature that corresponds to a TRUE condition."""
        self._trueConditionSignatures.append(signature)

    def learnFalseCondition(self, signature):
        """Record a response signature that corresponds to a FALSE condition."""
        self._falseConditionSignatures.append(signature)

    def predictCondition(self, signature):
        """
        Predict whether a response signature indicates TRUE or FALSE.
        Returns (prediction, confidence) where prediction is bool.
        Uses weighted feature comparison against learned patterns.
        """

        if not self._trueConditionSignatures or not self._falseConditionSignatures:
            return None, 0.0

        trueScore = self._computeSimilarityScore(signature, self._trueConditionSignatures)
        falseScore = self._computeSimilarityScore(signature, self._falseConditionSignatures)

        total = trueScore + falseScore
        if total == 0:
            return None, 0.0

        trueProb = trueScore / total
        prediction = trueProb > 0.5
        confidence = abs(trueProb - 0.5) * 2  # Normalize to 0..1

        return prediction, confidence

    def getAnomalyScore(self, signature):
        """
        Calculate how anomalous a response is compared to the baseline.
        High anomaly score suggests WAF interference or unusual server behavior.
        Returns float 0.0 (normal) to 1.0 (highly anomalous).
        """

        score = 0.0
        factors = 0

        # Content length anomaly
        if self._contentLengthHistory:
            mean = sum(self._contentLengthHistory) / len(self._contentLengthHistory)
            if mean > 0:
                deviation = abs(signature["content_length"] - mean) / mean
                score += min(deviation, 1.0) * self._patternWeights["content_length"]
                factors += self._patternWeights["content_length"]

        # Response time anomaly
        if self._responseTimeHistory and signature["response_time"] > 0:
            mean = sum(self._responseTimeHistory) / len(self._responseTimeHistory)
            if mean > 0:
                deviation = abs(signature["response_time"] - mean) / mean
                score += min(deviation, 1.0) * self._patternWeights["response_time"]
                factors += self._patternWeights["response_time"]

        # Status code anomaly
        if self._statusCodeDistribution:
            totalResponses = sum(self._statusCodeDistribution.values())
            codeFreq = self._statusCodeDistribution.get(signature["status_code"], 0)
            rarity = 1.0 - (codeFreq / totalResponses) if totalResponses > 0 else 1.0
            score += rarity * self._patternWeights["status_code"]
            factors += self._patternWeights["status_code"]

        # Error pattern anomaly
        if signature["has_error"]:
            score += self._patternWeights["error_pattern"]
        factors += self._patternWeights["error_pattern"]

        return score / factors if factors > 0 else 0.0

    def _computeStructuralHash(self, content):
        """Compute a hash of the structural layout of HTML content."""
        # Strip text content, keep only tags structure
        structure = re.sub(r">[^<]+<", "><", content)
        structure = re.sub(r"\s+", " ", structure)
        return hashlib.md5(structure.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def _computeSimilarityScore(self, signature, referenceSignatures):
        """Compute weighted similarity between a signature and reference set."""
        if not referenceSignatures:
            return 0.0

        totalScore = 0.0

        for ref in referenceSignatures:
            score = 0.0

            # Status code match
            if signature["status_code"] == ref["status_code"]:
                score += self._patternWeights["status_code"]

            # Content length similarity
            if ref["content_length"] > 0:
                diff = abs(signature["content_length"] - ref["content_length"])
                similarity = max(0, 1.0 - diff / max(ref["content_length"], 1))
                score += similarity * self._patternWeights["content_length"]

            # Response time similarity
            if ref["response_time"] > 0 and signature["response_time"] > 0:
                diff = abs(signature["response_time"] - ref["response_time"])
                similarity = max(0, 1.0 - diff / max(ref["response_time"], 1))
                score += similarity * self._patternWeights["response_time"]

            # Structural similarity
            if signature["structural_hash"] == ref.get("structural_hash"):
                score += self._patternWeights["structural"]

            # Error pattern match
            if signature["has_error"] == ref.get("has_error", False):
                score += self._patternWeights["error_pattern"]

            totalScore += score

        return totalScore / len(referenceSignatures)


class AIPayloadOptimizer(object):
    """
    Intelligently prioritizes and optimizes SQL injection payloads based on:
    - Target DBMS fingerprint
    - Historical success rates of payload types
    - WAF evasion requirements
    - Response pattern analysis
    """

    def __init__(self):
        self._payloadSuccessRates = {}
        self._techniqueScores = {
            PAYLOAD.TECHNIQUE.BOOLEAN: 0.5,
            PAYLOAD.TECHNIQUE.ERROR: 0.5,
            PAYLOAD.TECHNIQUE.UNION: 0.5,
            PAYLOAD.TECHNIQUE.STACKED: 0.5,
            PAYLOAD.TECHNIQUE.TIME: 0.5,
            PAYLOAD.TECHNIQUE.QUERY: 0.5,
        }
        self._dbmsPayloadWeights = {}
        self._totalTests = 0
        self._successfulTests = 0
        self._wafDetected = False
        self._blockedPatterns = set()

        self._initDbmsWeights()

    def _initDbmsWeights(self):
        """Initialize payload effectiveness weights per DBMS."""
        self._dbmsPayloadWeights = {
            DBMS.MYSQL: {
                PAYLOAD.TECHNIQUE.ERROR: 0.85,
                PAYLOAD.TECHNIQUE.UNION: 0.90,
                PAYLOAD.TECHNIQUE.BOOLEAN: 0.80,
                PAYLOAD.TECHNIQUE.TIME: 0.70,
                PAYLOAD.TECHNIQUE.STACKED: 0.40,
            },
            DBMS.PGSQL: {
                PAYLOAD.TECHNIQUE.ERROR: 0.80,
                PAYLOAD.TECHNIQUE.UNION: 0.85,
                PAYLOAD.TECHNIQUE.BOOLEAN: 0.75,
                PAYLOAD.TECHNIQUE.TIME: 0.75,
                PAYLOAD.TECHNIQUE.STACKED: 0.80,
            },
            DBMS.MSSQL: {
                PAYLOAD.TECHNIQUE.ERROR: 0.90,
                PAYLOAD.TECHNIQUE.UNION: 0.85,
                PAYLOAD.TECHNIQUE.BOOLEAN: 0.80,
                PAYLOAD.TECHNIQUE.TIME: 0.75,
                PAYLOAD.TECHNIQUE.STACKED: 0.85,
            },
            DBMS.ORACLE: {
                PAYLOAD.TECHNIQUE.ERROR: 0.80,
                PAYLOAD.TECHNIQUE.UNION: 0.75,
                PAYLOAD.TECHNIQUE.BOOLEAN: 0.70,
                PAYLOAD.TECHNIQUE.TIME: 0.60,
                PAYLOAD.TECHNIQUE.STACKED: 0.30,
            },
            DBMS.SQLITE: {
                PAYLOAD.TECHNIQUE.ERROR: 0.70,
                PAYLOAD.TECHNIQUE.UNION: 0.85,
                PAYLOAD.TECHNIQUE.BOOLEAN: 0.80,
                PAYLOAD.TECHNIQUE.TIME: 0.65,
                PAYLOAD.TECHNIQUE.STACKED: 0.50,
            },
        }

    def recordTestResult(self, technique, payload, success, dbms=None):
        """Record the result of a payload test to update success rates."""
        self._totalTests += 1

        key = (technique, self._getPayloadCategory(payload))
        if key not in self._payloadSuccessRates:
            self._payloadSuccessRates[key] = {"success": 0, "total": 0}

        self._payloadSuccessRates[key]["total"] += 1

        if success:
            self._successfulTests += 1
            self._payloadSuccessRates[key]["success"] += 1
            # Boost technique score on success
            if technique in self._techniqueScores:
                self._techniqueScores[technique] = min(
                    1.0, self._techniqueScores[technique] + 0.1
                )
        else:
            # Reduce technique score on failure
            if technique in self._techniqueScores:
                self._techniqueScores[technique] = max(
                    0.0, self._techniqueScores[technique] - 0.02
                )

    def recordBlockedPattern(self, pattern):
        """Record a pattern that was blocked (likely by WAF)."""
        self._blockedPatterns.add(pattern)
        self._wafDetected = True

    def getOptimalTechniqueOrder(self):
        """
        Return injection techniques ordered by predicted effectiveness.
        Combines historical success data with DBMS-specific knowledge.
        """

        scores = dict(self._techniqueScores)

        # Factor in DBMS-specific weights if known
        identifiedDbms = None
        if hasattr(kb, "dbms") and kb.dbms:
            identifiedDbms = kb.dbms
        elif hasattr(kb, "heuristicDbms") and kb.heuristicDbms:
            identifiedDbms = kb.heuristicDbms

        if identifiedDbms:
            dbmsWeights = self._dbmsPayloadWeights.get(identifiedDbms, {})
            for technique, weight in dbmsWeights.items():
                if technique in scores:
                    scores[technique] = scores[technique] * 0.6 + weight * 0.4

        # If WAF detected, deprioritize noisy techniques
        if self._wafDetected:
            scores[PAYLOAD.TECHNIQUE.UNION] *= 0.5
            scores[PAYLOAD.TECHNIQUE.STACKED] *= 0.4
            scores[PAYLOAD.TECHNIQUE.ERROR] *= 0.7
            scores[PAYLOAD.TECHNIQUE.TIME] *= 1.2  # Time-based often bypasses WAFs
            scores[PAYLOAD.TECHNIQUE.BOOLEAN] *= 1.1

        # Sort by score (highest first)
        return sorted(scores.keys(), key=lambda t: scores[t], reverse=True)

    def shouldSkipTest(self, test, place, parameter):
        """
        Determine if a test should be skipped based on AI analysis.
        Returns (should_skip, reason) tuple.
        """

        technique = test.stype if hasattr(test, "stype") else None

        # Skip if technique has very low success rate (after sufficient data)
        if technique and technique in self._techniqueScores:
            if self._totalTests > 20 and self._techniqueScores[technique] < 0.1:
                return True, "AI: technique has very low success rate (%.1f%%)" % (self._techniqueScores[technique] * 100)

        # If WAF detected, skip known blocked patterns
        if self._wafDetected and hasattr(test, "title"):
            title = test.title.upper()
            for blocked in self._blockedPatterns:
                if blocked.upper() in title:
                    return True, "AI: pattern likely blocked by WAF"

        return False, None

    def getPayloadScore(self, test):
        """Score a test payload for prioritization. Higher is better."""
        score = 50.0  # Base score

        technique = test.stype if hasattr(test, "stype") else None

        # Apply technique score
        if technique and technique in self._techniqueScores:
            score += self._techniqueScores[technique] * 30

        # Boost if matches identified DBMS
        identifiedDbms = None
        if hasattr(kb, "dbms") and kb.dbms:
            identifiedDbms = kb.dbms
        elif hasattr(kb, "heuristicDbms") and kb.heuristicDbms:
            identifiedDbms = kb.heuristicDbms

        if identifiedDbms and hasattr(test, "dbms"):
            if test.dbms and identifiedDbms in test.dbms:
                score += 20

        # Penalize if WAF detected and technique is noisy
        if self._wafDetected and technique:
            if technique in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.STACKED):
                score -= 15
            elif technique == PAYLOAD.TECHNIQUE.TIME:
                score += 10  # Time-based bypasses WAFs
            elif technique == PAYLOAD.TECHNIQUE.BOOLEAN:
                score += 5

        return score

    def getSuccessRate(self):
        """Get overall success rate of tests."""
        if self._totalTests == 0:
            return 0.0
        return self._successfulTests / self._totalTests

    def _getPayloadCategory(self, payload):
        """Categorize a payload for tracking purposes."""
        if not payload:
            return "unknown"
        payload = str(payload).upper()
        if "UNION" in payload:
            return "union"
        elif "AND" in payload or "OR" in payload:
            return "boolean"
        elif "SLEEP" in payload or "WAITFOR" in payload or "BENCHMARK" in payload:
            return "time"
        elif "EXTRACTVALUE" in payload or "UPDATEXML" in payload:
            return "error"
        else:
            return "other"


class AIWAFAnalyzer(object):
    """
    AI-powered WAF/IPS detection and fingerprinting.
    Identifies specific WAF products and suggests optimal bypass strategies.
    """

    WAF_SIGNATURES = {
        "ModSecurity": {
            "headers": [r"mod_security", r"NOYB"],
            "body": [r"mod_security", r"This error was generated by Mod_Security"],
            "codes": [403, 406, 501],
        },
        "Cloudflare": {
            "headers": [r"cf-ray", r"__cfduid", r"cf-cache-status", r"cloudflare"],
            "body": [r"Attention Required|Cloudflare", r"cloudflare-nginx"],
            "codes": [403, 503],
        },
        "AWS WAF": {
            "headers": [r"x-amzn-RequestId", r"X-AMZ-"],
            "body": [r"AWS WAF", r"Request blocked"],
            "codes": [403],
        },
        "Akamai": {
            "headers": [r"AkamaiGHost", r"X-Akamai"],
            "body": [r"Access Denied.*Akamai", r"Reference\s*#\d+\.\w+"],
            "codes": [403],
        },
        "Imperva/Incapsula": {
            "headers": [r"X-CDN.*Incapsula", r"incap_ses", r"visid_incap"],
            "body": [r"Incapsula incident", r"_Incapsula_Resource"],
            "codes": [403],
        },
        "F5 BIG-IP ASM": {
            "headers": [r"BigIP", r"BIGipServer", r"TS\w{6,}="],
            "body": [r"The requested URL was rejected", r"support ID"],
            "codes": [403],
        },
        "Sucuri": {
            "headers": [r"X-Sucuri", r"sucuri"],
            "body": [r"Sucuri Website Firewall", r"sucuri\.net"],
            "codes": [403],
        },
        "Barracuda": {
            "headers": [r"barra_counter_session"],
            "body": [r"Barracuda Web Application Firewall"],
            "codes": [403],
        },
        "Fortinet/FortiWeb": {
            "headers": [r"FORTIWAFSID", r"fortigate"],
            "body": [r"FortiWeb", r"\.fgt_redirect"],
            "codes": [403],
        },
        "Wordfence": {
            "headers": [],
            "body": [r"Generated by Wordfence", r"wordfence"],
            "codes": [403, 503],
        },
    }

    BYPASS_STRATEGIES = {
        "ModSecurity": [
            "space2comment", "between", "randomcase", "percentage",
            "charencode", "greatest", "least", "modsecurityversioned",
        ],
        "Cloudflare": [
            "space2comment", "between", "charunicodeencode",
            "randomcase", "htmlencode", "scientfic",
        ],
        "AWS WAF": [
            "space2comment", "charencode", "between",
            "randomcase", "overlongutf8",
        ],
        "Akamai": [
            "space2morecomment", "between", "charunicodeencode",
            "randomcase", "percentage",
        ],
        "Imperva/Incapsula": [
            "space2comment", "between", "charunicodeencode",
            "randomcase", "versionedkeywords",
        ],
        "F5 BIG-IP ASM": [
            "space2comment", "between", "chardoubleencode",
            "randomcase", "charencode",
        ],
        "Sucuri": [
            "space2comment", "between", "charencode",
            "randomcase", "versionedmorekeywords",
        ],
        "Barracuda": [
            "space2comment", "between", "randomcase",
            "charencode", "percentage",
        ],
        "Fortinet/FortiWeb": [
            "space2comment", "between", "randomcase",
            "charunicodeencode", "charencode",
        ],
        "Wordfence": [
            "space2comment", "between", "charencode",
            "randomcase", "commentbeforeparentheses",
        ],
        "_default": [
            "space2comment", "between", "randomcase",
            "charencode", "percentage",
        ],
    }

    def __init__(self):
        self._identifiedWafs = []
        self._responseAnalysis = []
        self._blockSignatures = []

    def analyzeWafResponse(self, response, headers, statusCode):
        """
        Analyze response to identify WAF product.
        Returns list of (waf_name, confidence) tuples.
        """

        results = []
        headersStr = str(headers) if headers else ""

        for wafName, signatures in self.WAF_SIGNATURES.items():
            score = 0.0
            maxScore = 0.0

            # Check headers
            for pattern in signatures["headers"]:
                maxScore += 1.0
                if re.search(pattern, headersStr, re.I):
                    score += 1.0

            # Check body
            if response:
                for pattern in signatures["body"]:
                    maxScore += 1.0
                    if re.search(pattern, response, re.I):
                        score += 1.0

            # Check status codes
            if signatures["codes"]:
                maxScore += 0.5
                if statusCode in signatures["codes"]:
                    score += 0.5

            if maxScore > 0:
                confidence = score / maxScore
                if confidence > 0.3:
                    results.append((wafName, confidence))

        # Sort by confidence descending
        results.sort(key=lambda x: x[1], reverse=True)
        self._identifiedWafs = results
        return results

    def getRecommendedTampers(self, wafName=None):
        """Get recommended tamper scripts for the identified or specified WAF."""
        if wafName:
            return list(self.BYPASS_STRATEGIES.get(wafName, self.BYPASS_STRATEGIES["_default"]))

        if self._identifiedWafs:
            topWaf = self._identifiedWafs[0][0]
            return list(self.BYPASS_STRATEGIES.get(topWaf, self.BYPASS_STRATEGIES["_default"]))

        return list(self.BYPASS_STRATEGIES["_default"])

    def getIdentifiedWafs(self):
        """Return list of identified WAFs with confidence scores."""
        return list(self._identifiedWafs)


class AISmartScan(object):
    """
    AI-powered intelligent scanning coordinator.
    Orchestrates scan strategy based on cumulative intelligence gathered
    during the testing process. Provides adaptive decision-making for:
    - When to stop testing a parameter
    - How to adjust technique ordering
    - When to suggest tamper scripts
    - How to optimize request rate
    """

    def __init__(self):
        self.responseAnalyzer = AIResponseAnalyzer()
        self.payloadOptimizer = AIPayloadOptimizer()
        self.wafAnalyzer = AIWAFAnalyzer()
        self._scanStartTime = None
        self._requestCount = 0
        self._blockCount = 0
        self._adaptiveDelay = 0
        self._insights = []
        self._parameterRisk = {}

    def startScan(self):
        """Initialize AI scan tracking."""
        self._scanStartTime = time.time()
        self._requestCount = 0
        self._blockCount = 0
        self._insights = []

        infoMsg = "[AI] Smart scan engine initialized"
        logger.info(infoMsg)

    def recordRequest(self, response, statusCode, responseTime=None, payload=None, technique=None):
        """Record a request/response pair for AI analysis."""
        self._requestCount += 1

        signature = self.responseAnalyzer.analyzeResponse(response, statusCode, responseTime)

        # Detect potential WAF blocking
        if statusCode in (403, 406, 429, 501, 503):
            self._blockCount += 1
            if payload:
                self.payloadOptimizer.recordBlockedPattern(str(payload)[:50])

            # Adaptive delay on blocks
            if self._blockCount > 3:
                self._adaptiveDelay = min(self._adaptiveDelay + 0.5, 5.0)

        return signature

    def recordTestResult(self, technique, payload, success, dbms=None):
        """Forward test results to the payload optimizer."""
        self.payloadOptimizer.recordTestResult(technique, payload, success, dbms)

    def analyzeWaf(self, response, headers, statusCode):
        """Analyze WAF presence and type."""
        wafs = self.wafAnalyzer.analyzeWafResponse(response, headers, statusCode)

        if wafs:
            topWaf, confidence = wafs[0]
            self._insights.append(
                "WAF identified: %s (confidence: %.0f%%)" % (topWaf, confidence * 100)
            )

            recommTampers = self.wafAnalyzer.getRecommendedTampers()
            if recommTampers:
                self._insights.append(
                    "Recommended tamper scripts: %s" % ", ".join(recommTampers[:3])
                )

        return wafs

    def assessParameterRisk(self, place, parameter, value):
        """
        Assess how likely a parameter is to be injectable.
        Returns risk score from 0.0 to 1.0.
        """

        score = 0.5  # Base score

        paramLower = parameter.lower() if parameter else ""
        valueLower = str(value).lower() if value else ""

        # High-risk parameter names
        highRiskNames = [
            "id", "uid", "pid", "nid", "catid", "itemid", "page", "pageid",
            "articleid", "productid", "newsid", "postid", "userid", "memberid",
            "num", "no", "number", "idx", "index", "code",
        ]
        medRiskNames = [
            "name", "user", "username", "login", "email", "query", "search",
            "keyword", "key", "filter", "sort", "order", "type", "category",
            "action", "cmd", "view", "file", "path", "dir", "table", "col",
        ]
        lowRiskNames = [
            "token", "csrf", "nonce", "hash", "session", "sid", "callback",
            "timestamp", "ts", "v", "ver", "version", "format", "lang",
        ]

        # Check parameter name matches
        for name in highRiskNames:
            if name == paramLower or paramLower.endswith(name) or paramLower.startswith(name):
                score += 0.3
                break

        for name in medRiskNames:
            if name == paramLower or paramLower.endswith(name):
                score += 0.15
                break

        for name in lowRiskNames:
            if name == paramLower or paramLower.endswith(name):
                score -= 0.3
                break

        # Numeric values are more likely injectable
        if valueLower.isdigit():
            score += 0.15
        elif re.match(r"^[\d.]+$", valueLower):
            score += 0.1

        # Short single-word values are more likely parameters, not tokens
        if len(valueLower) < 10 and " " not in valueLower:
            score += 0.05

        # Long hex/base64-like values are likely tokens
        if len(valueLower) > 30 and re.match(r"^[a-f0-9]+$", valueLower):
            score -= 0.25
        if len(valueLower) > 20 and re.match(r"^[a-zA-Z0-9+/=]+$", valueLower):
            score -= 0.2

        score = max(0.0, min(1.0, score))
        self._parameterRisk[(place, parameter)] = score
        return score

    def getAdaptiveDelay(self):
        """Get recommended delay between requests based on WAF behavior."""
        return self._adaptiveDelay

    def getOptimalTechniqueOrder(self):
        """Get AI-recommended technique testing order."""
        return self.payloadOptimizer.getOptimalTechniqueOrder()

    def shouldContinueTesting(self, parameter, testsRun, injectionFound):
        """
        Determine if testing should continue for a parameter.
        Returns (should_continue, reason) tuple.
        """

        # Always continue if injection found (explore all techniques)
        if injectionFound:
            return True, "Injection found, exploring techniques"

        # If > 50 tests with no result and success rate is very low, consider stopping
        if testsRun > 50:
            rate = self.payloadOptimizer.getSuccessRate()
            if rate < 0.01:
                riskScore = self._parameterRisk.get(parameter, 0.5)
                if riskScore < 0.3:
                    return False, "AI: Low-risk parameter with no results after %d tests" % testsRun

        return True, "Continue testing"

    def getScanSummary(self):
        """Generate AI-powered scan analysis summary."""
        elapsed = time.time() - self._scanStartTime if self._scanStartTime else 0

        summary = []
        summary.append("[AI] Scan Analysis Summary")
        summary.append("=" * 50)
        summary.append("Total requests: %d" % self._requestCount)

        if elapsed > 0:
            summary.append("Scan duration: %.1f seconds" % elapsed)
            summary.append("Request rate: %.1f req/s" % (self._requestCount / elapsed if elapsed > 0 else 0))

        if self._blockCount > 0:
            summary.append("Blocked requests: %d (%.1f%%)" % (
                self._blockCount, (self._blockCount / max(self._requestCount, 1)) * 100
            ))

        wafs = self.wafAnalyzer.getIdentifiedWafs()
        if wafs:
            summary.append("WAF/IPS detected: %s" % ", ".join(
                "%s (%.0f%%)" % (w, c * 100) for w, c in wafs
            ))
            tampers = self.wafAnalyzer.getRecommendedTampers()
            if tampers:
                summary.append("Recommended tampers: %s" % ", ".join(tampers[:5]))

        successRate = self.payloadOptimizer.getSuccessRate()
        summary.append("Test success rate: %.1f%%" % (successRate * 100))

        # Technique effectiveness ranking
        techOrder = self.payloadOptimizer.getOptimalTechniqueOrder()
        techNames = {
            PAYLOAD.TECHNIQUE.BOOLEAN: "Boolean-based",
            PAYLOAD.TECHNIQUE.ERROR: "Error-based",
            PAYLOAD.TECHNIQUE.UNION: "UNION query",
            PAYLOAD.TECHNIQUE.STACKED: "Stacked queries",
            PAYLOAD.TECHNIQUE.TIME: "Time-based",
            PAYLOAD.TECHNIQUE.QUERY: "Inline query",
        }
        ranking = [techNames.get(t, str(t)) for t in techOrder[:4]]
        summary.append("Technique ranking: %s" % " > ".join(ranking))

        if self._insights:
            summary.append("\nInsights:")
            for insight in self._insights:
                summary.append("  - %s" % insight)

        return "\n".join(summary)

    def generateRecommendations(self):
        """Generate actionable recommendations based on scan analysis."""
        recommendations = []

        # WAF-related recommendations
        wafs = self.wafAnalyzer.getIdentifiedWafs()
        if wafs:
            topWaf = wafs[0][0]
            tampers = self.wafAnalyzer.getRecommendedTampers(topWaf)
            if tampers and not conf.get("tamper"):
                recommendations.append(
                    "WAF detected (%s). Try: --tamper=%s" % (topWaf, ",".join(tampers[:3]))
                )

        # Request rate recommendations
        if self._blockCount > 5:
            recommendations.append(
                "Multiple blocks detected. Consider using: --delay=%.1f --random-agent" % max(1.0, self._adaptiveDelay)
            )

        # Technique recommendations
        successRate = self.payloadOptimizer.getSuccessRate()
        if self._requestCount > 30 and successRate < 0.02:
            recommendations.append(
                "Very low success rate. Consider: --level=5 --risk=3"
            )

        if self.payloadOptimizer._wafDetected:
            recommendations.append(
                "WAF detected. Time-based blind techniques may be more effective"
            )

        return recommendations


# Global AI engine instance
_aiEngine = None


def getAIEngine():
    """Get or create the global AI engine instance."""
    global _aiEngine
    if _aiEngine is None:
        _aiEngine = AISmartScan()
    return _aiEngine


def resetAIEngine():
    """Reset the AI engine for a new scan."""
    global _aiEngine
    _aiEngine = AISmartScan()
    return _aiEngine
