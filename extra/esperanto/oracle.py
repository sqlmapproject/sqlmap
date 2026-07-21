#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from contextlib import contextmanager

from .records import OracleUndecided
from .records import QueryBudgetExceeded


class _OracleCore(object):
    """_OracleCore

    the boolean-oracle contract + tiny SQL formatters (nothing dialect-specific)."""

    @contextmanager
    def _probePhase(self):
        # mark a candidate-rung laddering section (discovery or lazy _ensure*): while
        # active, a host oracle may safely read an undecidable probe as False ("this
        # rung is unusable"), whereas outside it an undecidable READ must stay undecided
        prev = self._probing
        self._probing = True
        try:
            yield
        finally:
            self._probing = prev

    def _emit(self, value):
        # per-VALUE feedback is for user-requested data reads only, NOT capability/discovery probes
        # (charset, lazy hexfn, cast canary - all wrapped in _probePhase): surfacing an internal
        # probe value as "retrieved: <x>" reads as a stray, out-of-context line to the user.
        if self._progress and value not in (None, "") and not self._probing:
            try:
                self._progress(value)
            except Exception:
                pass

    def _emitChar(self, partial, total):
        # live per-character feedback DURING a long extraction, so the user sees movement
        # instead of a frozen prompt (a whole framed row is one long silent read otherwise) -
        # suppressed during probe phases (see _emit) so a discovery probe doesn't animate
        if self._charProgress and not self._probing:
            try:
                self._charProgress(partial, total)
            except Exception:
                pass

    def _probe(self, condition):
        # ONE tri-state evaluation: True / False / None(persistent error). a raised
        # oracle is retried (transient) before being reported as an error - a
        # wrong-dialect probe legitimately errors, but a flaky connection must not
        # be allowed to read as a definitive False. counts every actual oracle call.
        for _ in range(self.retries + 1):
            if self.max_queries is not None and self._queries >= self.max_queries:
                raise QueryBudgetExceeded("oracle query budget exhausted at %d calls" % self._queries)
            self._queries += 1
            try:
                observed = self.oracle(condition)
            except Exception:
                continue
            # STRICT: only a real bool is an observation. None/0/''/other must not be
            # coerced to False (that silently corrupts bisection) - treat as undecided.
            if observed is True or observed is False:
                return observed
        return None

    def _ask(self, condition):
        # decided boolean, or raise OracleUndecided - NEVER manufacture False from an
        # unobservable probe (that would silently corrupt blind bisection). the oracle
        # must itself return False for unsupported/rejected SQL; a raised probe means
        # "could not observe" and, absent a quorum, is fatal.
        if self.quorum <= 1:
            r = self._probe(condition)
            if self.verbose:
                print("  [%s] %s" % ("T" if r else ("E" if r is None else "f"), condition))
            if r is None:
                # while laddering CANDIDATE rungs an undecidable/erroring probe (oracle
                # returned None OR raised - both surface here as None) means "this rung is
                # unusable", so read it as False and let the ladder move on; only OUTSIDE
                # probing (reading committed data) is it fatal, so a flaky read never
                # silently coerces to a definite bit
                if self._probing:
                    return False
                self._errors += 1
                raise OracleUndecided("oracle could not decide: %s" % condition)
            return r

        samples = 2 * self.quorum - 1
        yes = no = tries = 0
        while (yes + no) < samples and tries < samples + self.quorum + 2:
            tries += 1
            r = self._probe(condition)
            if r is None:
                self._errors += 1
                continue
            yes, no = (yes + 1, no) if r else (yes, no + 1)
            if yes >= self.quorum or no >= self.quorum:
                break
        if self.verbose:
            state = "T" if yes >= self.quorum else ("f" if no >= self.quorum else "E")
            print("  [%s %d:%d] %s" % (state, yes, no, condition))
        if yes >= self.quorum:
            return True
        if no >= self.quorum:
            return False
        if self._probing:               # candidate rung the vote couldn't settle -> unusable, not fatal
            return False
        raise OracleUndecided("oracle vote undecided: %s (%d true / %d false)" % (condition, yes, no))

    def _sub(self, expr, pos, length):
        # pos is always passed 1-based; adjust for a 0-based dialect if discovered
        p = pos if self.dialect.substring.get("index_base", 1) == 1 else pos - 1
        return self.dialect.substring[1].format(expr=expr, pos=p, len=length)

    def _len(self, expr):
        return self.dialect.length[1].format(expr=expr)

    def _sanity(self):
        return self._ask("1=1") and not self._ask("1=2") and \
               self._ask("'a'='a'") and not self._ask("'a'='b'")

    def _exists(self, source, column="1", alias=None):
        # does `source` (a table/catalog) - and optionally `column` in it - resolve?
        # WITHOUT COUNT (which a WAF may filter): a scalar subquery over it is NULL when
        # it resolves (WHERE 1=0 -> 0 rows) and ERRORS -> False when it doesn't. Works
        # for empty tables too. `column` is passed BARE so a nonexistent one errors,
        # rather than being taken as a string literal (SQLite quirk) and passing every
        # fake name. When `alias` is set the column is ALIAS-QUALIFIED (`e.col`) so a bare
        # candidate can't silently resolve to a KEYWORD/FUNCTION (USER, CURRENT_USER, ...)
        # or an unrelated in-scope name - an alias-qualified unknown is always an error.
        if alias:
            return self._ask("(SELECT %s.%s FROM %s %s WHERE 1=0) IS NULL" % (alias, column, source, alias))
        return self._ask("(SELECT %s FROM %s WHERE 1=0) IS NULL" % (column, source))
