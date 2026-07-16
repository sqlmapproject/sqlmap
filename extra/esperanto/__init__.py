"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

esperanto - a DBMS-agnostic SQL poking prototype.

Given only a boolean oracle - a callable oracle(condition) -> bool that reports
whether an arbitrary SQL boolean expression holds at the target - this discovers
the target's SQL dialect from scratch (concatenation operator, substring / length
/ char-code functions, string comparison, catalog surface) and then extracts data
char-by-char WITHOUT ever being told which DBMS is on the other end.

The candidate variants below are harvested from sqlmap's own data/xml/queries.xml
across all 31 supported DBMSes - the point is to reuse that accumulated knowledge
as a single "esperanto" the tool speaks at any backend, rather than fingerprinting
first and loading one dialect.

This is a self-contained research prototype (no sqlmap imports); run it directly
for a built-in self-test against an in-memory SQLite oracle.
"""

from .engine import Esperanto
from .engine import hostExtract
from .handler import buildHandler
from .records import Cap, ExtractResult, BulkResult, Dialect, InferenceStrategy
from .records import OracleUndecided, QueryBudgetExceeded
