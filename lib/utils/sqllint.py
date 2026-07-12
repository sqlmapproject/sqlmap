#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import re

try:
    from lib.core.data import kb
    from lib.core.data import paths
    from lib.core.common import getFileItems
except ImportError:
    kb = paths = None
    getFileItems = None

# Token type constants (kept short/local; this is a self-contained lexer)
T_WS = "ws"
T_LCOMMENT = "lcomment"
T_BCOMMENT = "bcomment"
T_STR = "str"                # closed string literal ('...' or "...")
T_UNTERM = "unterm"          # unterminated string literal (open quote to end)
T_QID = "qid"               # quoted identifier (`...` or [...])
T_NUM = "num"
T_IDENT = "ident"           # bare identifier (not a keyword)
T_KEYWORD = "keyword"       # identifier whose upper() is a known SQL keyword
T_OP = "op"
T_COMMA = "comma"
T_DOT = "dot"
T_SEMI = "semi"
T_LPAREN = "lparen"
T_RPAREN = "rparen"
T_OTHER = "other"           # anything the lexer could not classify

# Master lexer: ORDER MATTERS (longer / more specific patterns first)
_LEXER = re.compile(r"""
      (?P<%s>\s+)
    | (?P<%s>(?:--|\#)[^\n]*)
    | (?P<%s>/\*.*?\*/)
    | (?P<%s>'(?:''|[^'])*'|"(?:""|[^"])*")
    | (?P<%s>`[^`]*`|\[[^\]]*\])
    | (?P<%s>0[xX][0-9A-Fa-f]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)
    | (?P<%s>(?:[A-Za-z_@$]|[^\x00-\x7f])(?:[A-Za-z0-9_@$]|[^\x00-\x7f])*)
    | (?P<%s><=|>=|<>|!=|==|<<|>>|\|\||&&|::|:=|[-+*/%%=<>!~&|^:])
    | (?P<%s>,)
    | (?P<%s>\.)
    | (?P<%s>;)
    | (?P<%s>\()
    | (?P<%s>\))
""" % (T_WS, T_LCOMMENT, T_BCOMMENT, T_STR, T_QID, T_NUM, T_IDENT, T_OP,
       T_COMMA, T_DOT, T_SEMI, T_LPAREN, T_RPAREN), re.VERBOSE | re.DOTALL)

# operand-producing token types (something that evaluates to a value)
_OPERANDS = frozenset((T_NUM, T_STR, T_IDENT, T_QID, T_RPAREN))

# operands trustworthy as the left side of a "missing separator" check.
# a string is excluded because break-out payloads routinely produce a fake
# merged string (e.g. "1' AND '1"->"' AND '") followed by a bare number; a
# number is excluded because some dialects legitimately space-separate two
# numbers (e.g. HSQLDB "LIMIT <offset> <limit>")
_HARD_OPERANDS = frozenset((T_IDENT, T_RPAREN))

# binary keyword operators (need an operand on both sides)
_BINARY_KEYWORDS = frozenset(("AND", "OR", "XOR", "LIKE", "RLIKE", "REGEXP", "DIV", "MOD"))

# binary symbolic operators (unary +/-/~ excluded; '*' excluded as it doubles
# as the SELECT/COUNT wildcard)
_BINARY_SYMBOLS = frozenset(("=", "<>", "!=", "<", ">", "<=", ">=", "/", "%", "||", "&&", "|", "&", "^"))

# clause-introducing keywords that signal a dangling list item when they sit
# right after a comma ("SELECT a,b, FROM t"). GROUP/ORDER/LIMIT/OFFSET are
# excluded on purpose - they double as very common column names, so a bare
# "a,limit,b" would false-positive.
_CLAUSE_KEYWORDS = frozenset(("FROM", "WHERE", "HAVING", "INTO"))

# single-occurrence clause keywords (at most one per SELECT scope) with no
# identifier-collision risk - unlike GROUP/ORDER, which double as column names.
# a repeat at the same paren-depth is the 'WHERE x WHERE y' structural bug (e.g.
# a schema filter appended onto a base query that already carries a WHERE).
_SINGLE_CLAUSE_KEYWORDS = frozenset(("WHERE", "HAVING"))

# set operators that begin a fresh SELECT, resetting single-occurrence clauses at
# the current scope ('a WHERE x UNION b WHERE y' is legal; two WHEREs are not).
_SET_OPERATORS = frozenset(("UNION", "EXCEPT", "INTERSECT", "MINUS"))

# sqlmap's own templating markers. If any survives into a *final* outbound payload
# a substitution failed upstream (agent.py / cleanupPayload / queries.xml) - always
# a bug. Matched on the raw payload because a marker can leak anywhere (bare, inside
# a string, or where the lexer would otherwise read it as an MSSQL [identifier]).
_LEFTOVER_MARKER = re.compile(
    r"\[(?:RANDNUM\d*|RANDSTR\d*|INFERENCE|SLEEPTIME|DELAYED|DELIMITER_START|DELIMITER_STOP"
    r"|ORIGVALUE|ORIGINAL|GENERIC_SQL_COMMENT|QUERY|UNION|CHAR|COLSTART|COLSTOP|DB"
    r"|SINGLE_QUOTE|DOUBLE_QUOTE|AT_REPLACE|SPACE_REPLACE|DOLLAR_REPLACE|HASH_REPLACE)\]")

# SQL words whose near-miss spelling in a structural position is almost always a
# broken payload, not a legitimate identifier (deliberately smaller than the full
# keyword list): catches payload-builder typos like UNI1ON/SEL2ECT/ORD2ER without
# flagging arbitrary application identifiers.
# only length>=5 structural keywords: short ones (ON/NOT/IN/IS/BY/OR/AND/ALL/
# FROM/LIKE/NULL/...) are too easily near-missed by real column names (note->NOT,
# ono->ON), which the real-identifier stress test proved would false-positive.
_NEAR_KEYWORD_TARGETS = frozenset((
    "SELECT", "UNION", "DISTINCT", "GROUP", "ORDER", "HAVING", "LIMIT",
    "OFFSET", "WHERE", "INNER", "RIGHT", "OUTER", "CROSS", "REGEXP", "RLIKE"))

# single-char substitutions seen in accidental mutation/test edits
_DIGIT_KEYWORD_ALIASES = {"0": "O", "1": "I", "2": "E", "3": "E", "4": "A", "5": "S", "7": "T", "8": "B"}

_CLAUSE_STARTERS = frozenset((
    "SELECT", "UNION", "FROM", "WHERE", "GROUP", "ORDER", "HAVING", "LIMIT",
    "OFFSET", "INTO", "JOIN", "ON", "AND", "OR"))

_KEYWORDS_CACHE = None


class Token(object):
    __slots__ = ("type", "value", "start", "end")

    def __init__(self, type_, value, start, end):
        self.type = type_
        self.value = value
        self.start = start
        self.end = end


def _word(token):
    if token is not None and token.type in (T_IDENT, T_KEYWORD):
        return token.value.upper()
    return None


def _atClauseBoundary(prev):
    return prev is None or prev.type in (T_LPAREN, T_RPAREN, T_SEMI, T_COMMA) or \
           (prev.type == T_OP and prev.value not in (".",)) or \
           (prev.type == T_KEYWORD and prev.value.upper() in _CLAUSE_STARTERS)


def _editWithin1(a, b):
    """Damerau-Levenshtein distance <= 1 (one insertion, deletion, substitution
    or adjacent transposition). Catches every single-char keyword typo class."""
    la, lb = len(a), len(b)
    if a == b or abs(la - lb) > 1:
        return a == b
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:                                                   # substitution
            return True
        if len(diff) == 2 and diff[1] == diff[0] + 1 and \
           a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]:            # transposition
            return True
        return False
    shorter, longer = (a, b) if la < lb else (b, a)                          # deletion/insertion
    for i in range(len(longer)):
        if shorter == longer[:i] + longer[i + 1:]:
            return True
    return False


def _nearKeywordCandidates(value):
    """
    Structural SQL keywords one single-char typo away from an identifier
    (Damerau distance 1; NOT generic fuzzy matching over the whole keyword file).

    >>> sorted(_nearKeywordCandidates("UNI1ON"))
    ['UNION']
    >>> sorted(_nearKeywordCandidates("SEL2ECT"))
    ['SELECT']
    >>> sorted(_nearKeywordCandidates("UrNION"))
    ['UNION']
    >>> sorted(_nearKeywordCandidates("UNIN"))
    ['UNION']
    >>> sorted(_nearKeywordCandidates("UNOIN"))
    ['UNION']
    """
    upper = value.upper()
    if upper in _NEAR_KEYWORD_TARGETS or len(upper) < 4:
        return set()
    return set(target for target in _NEAR_KEYWORD_TARGETS if _editWithin1(upper, target))


def _nearKeywordIsStructural(sig, index, keyword):
    """True when a near-keyword identifier sits where that keyword is expected."""
    prev = sig[index - 1] if index > 0 else None
    nxt = sig[index + 1] if index + 1 < len(sig) else None
    prevWord = _word(prev)
    nextWord = _word(nxt)

    if keyword == "UNION":
        return nextWord in ("ALL", "DISTINCT", "SELECT") and \
               prevWord not in ("SELECT", "FROM", "WHERE", "GROUP", "ORDER", "BY", "HAVING", "LIMIT", "OFFSET", "JOIN", "ON", "AS")

    if keyword == "SELECT":
        return prev is None or prev.type in (T_LPAREN, T_SEMI) or prevWord in ("UNION", "ALL", "DISTINCT", "EXCEPT", "INTERSECT")

    if keyword in ("ORDER", "GROUP"):
        return nextWord == "BY"

    if keyword == "BY":
        return prevWord in ("ORDER", "GROUP")

    if keyword in ("AND", "OR", "LIKE", "REGEXP", "RLIKE", "IN", "IS"):
        return prev is not None and nxt is not None and prev.type in _OPERANDS and nxt.type in _OPERANDS.union((T_LPAREN,))

    if keyword in ("FROM", "WHERE", "HAVING", "LIMIT", "OFFSET", "INTO", "JOIN", "ON"):
        return _atClauseBoundary(prev) or prevWord in ("SELECT", "UPDATE", "DELETE", "INSERT", "FROM", "WHERE", "HAVING")

    if keyword in ("ALL", "DISTINCT"):
        return prevWord in ("UNION", "SELECT")

    if keyword in ("NULL", "NOT"):
        return _atClauseBoundary(prev)

    return False


def _keywords():
    global _KEYWORDS_CACHE

    if kb is not None and getattr(kb, "keywords", None):
        return kb.keywords

    if _KEYWORDS_CACHE is not None:
        return _KEYWORDS_CACHE

    retVal = set()

    candidate = None
    if paths is not None and getattr(paths, "SQL_KEYWORDS", None):
        candidate = paths.SQL_KEYWORDS
    else:
        # self-sufficient fallback (e.g. bare doctest run before boot)
        candidate = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "txt", "keywords.txt")

    try:
        if getFileItems is not None:
            retVal = set(getFileItems(candidate))
        else:
            with open(candidate) as f:
                retVal = set(_.strip().upper() for _ in f if _.strip() and not _.startswith('#'))
    except Exception:
        pass

    _KEYWORDS_CACHE = retVal
    return retVal


def tokenize(sql, keywords=None):
    """
    Fragment-tolerant lexer. Returns a list of Token objects (whitespace kept
    so callers can reason about token gluing, e.g. '1UNION').

    >>> [t.type for t in tokenize("id 1") if t.type != 'ws']
    ['ident', 'num']
    >>> [t.type for t in tokenize("1foo") if t.type != 'ws']
    ['num', 'ident']
    """
    if keywords is None:
        keywords = _keywords()

    retVal = []
    pos = 0
    length = len(sql)

    while pos < length:
        match = _LEXER.match(sql, pos)
        if match:
            type_ = match.lastgroup
            value = match.group()
            if type_ == T_IDENT and value.upper() in keywords:
                type_ = T_KEYWORD
            retVal.append(Token(type_, value, pos, match.end()))
            pos = match.end()
        else:
            char = sql[pos]
            if char in "'\"`[":
                # an opening quote/bracket that never closes -> unterminated to end
                retVal.append(Token(T_UNTERM, sql[pos:], pos, length))
                pos = length
            else:
                retVal.append(Token(T_OTHER, char, pos, pos + 1))
                pos += 1

    return retVal


def _significant(tokens):
    """Tokens that carry structure (drop whitespace and comments)."""
    return [_ for _ in tokens if _.type not in (T_WS, T_LCOMMENT, T_BCOMMENT)]


def _isBinary(token):
    if token.type == T_KEYWORD:
        return token.value.upper() in _BINARY_KEYWORDS
    if token.type == T_OP:
        return token.value in _BINARY_SYMBOLS
    return False


def checkSanity(sql, keywords=None):
    """
    Fragment-tolerant SQL sanity check. Models locally-valid SQL and reports
    only *interior* impossibilities - constructs that no server-side prefix or
    suffix could ever make legal. Dangling quotes/parens at the edges are
    tolerated (the surrounding query supplies the other half).

    Returns a list of human-readable issue strings (empty == looks sane).

    Assumes SQL keyword operators (AND/OR/LIKE/...) are used as operators, not
    as user identifiers named after a keyword (some engines, e.g. SQLite, allow
    a column literally named "LIKE") - injection payloads never do the latter.

    >>> checkSanity("1 AND 1=1")
    []
    >>> checkSanity("1') UNION SELECT NULL-- -")
    []
    >>> bool(checkSanity("(SELECT id 1 FROM users)"))
    True
    >>> bool(checkSanity("1UNION SELECT NULL"))
    True
    >>> bool(checkSanity("SELECT a FROM t WHERE x=1 WHERE y=2"))
    True
    >>> checkSanity("SELECT a FROM t WHERE x=1 UNION SELECT b FROM u WHERE y=2")
    []
    """
    if not sql:
        return []

    if keywords is None:
        keywords = _keywords()

    issues = []

    # -- residual templating markers (upstream substitution failed) --------
    for match in _LEFTOVER_MARKER.finditer(sql):
        issues.append("leftover marker '%s' at offset %d" % (match.group(0), match.start()))

    tokens = tokenize(sql, keywords)

    # -- edge tolerance for unterminated strings ---------------------------
    # A trailing open quote at paren-depth 0 is a legitimate break-out. One
    # that opens *inside* a group (depth > 0) has swallowed a needed ')', i.e.
    # an odd quote count within an owned scope (the classic "users'" abomination).
    depth = 0
    unterminated = False
    for token in tokens:
        if token.type == T_LPAREN:
            depth += 1
        elif token.type == T_RPAREN:
            depth -= 1
        elif token.type == T_UNTERM:
            if depth > 0:
                issues.append("odd quote inside a parenthesized scope at offset %d" % token.start)
            unterminated = True
            break

    # unclosed '(' (a dropped ')'): well-formed payloads NEVER end paren-positive
    # (leading break-out ')' only ever makes depth negative), so this is 0-FP.
    if not unterminated and depth > 0:
        issues.append("unbalanced parentheses (%d unclosed '(')" % depth)

    sig = _significant(tokens)

    for i in range(len(sig)):
        cur = sig[i]
        prev = sig[i - 1] if i > 0 else None
        nxt = sig[i + 1] if i + 1 < len(sig) else None

        # a keyword operator immediately followed by '(' is a function call
        # (e.g. the SQLite/MySQL LIKE(a, b) function), not a binary operator
        curIsFunc = cur.type == T_KEYWORD and nxt is not None and nxt.type == T_LPAREN
        curBinary = _isBinary(cur) and not curIsFunc

        # -- keyword near-miss in a structural position: UNI1ON/SEL2ECT/ORD2ER
        if cur.type == T_IDENT:
            for keyword in sorted(_nearKeywordCandidates(cur.value)):
                if _nearKeywordIsStructural(sig, i, keyword):
                    issues.append("keyword typo '%s' (near '%s') at offset %d" % (cur.value, keyword, cur.start))
                    break

        # -- UNION must continue with SELECT/ALL/DISTINCT/'(' (catches a glued or
        #    corrupted continuation like 'UNION ALLSELECT' -> UNION <identifier>)
        if cur.type == T_KEYWORD and cur.value.upper() == "UNION" and nxt is not None:
            if not (nxt.type == T_LPAREN or (nxt.type == T_KEYWORD and nxt.value.upper() in ("SELECT", "ALL", "DISTINCT"))):
                issues.append("UNION not followed by SELECT/ALL/DISTINCT at offset %d" % cur.start)

        # -- digit glued to a keyword: '1UNION', '5108AND' (a digit-started
        #    identifier like '4images' is legitimate and must NOT trip this)
        if cur.type == T_NUM and nxt is not None and nxt.start == cur.end and nxt.type == T_KEYWORD:
            issues.append("digit glued to a keyword ('%s%s') at offset %d" % (cur.value, nxt.value, cur.start))

        # -- operand directly followed by a bare number: 'id 1' ------------
        # a numeric literal can never be an alias, so this is always broken
        if cur.type == T_NUM and prev is not None and prev.type in _HARD_OPERANDS:
            issues.append("missing separator before number '%s' at offset %d" % (cur.value, cur.start))

        # -- degenerate parenthesis / punctuation adjacency ----------------
        if prev is not None:
            pair = (prev.type, cur.type)
            if pair == (T_COMMA, T_COMMA):
                issues.append("empty list item (',,') at offset %d" % cur.start)
            elif pair == (T_LPAREN, T_COMMA):
                issues.append("comma right after '(' at offset %d" % cur.start)
            elif pair == (T_COMMA, T_RPAREN):
                issues.append("comma right before ')' at offset %d" % cur.start)
            elif prev.type == T_KEYWORD and prev.value.upper() == "SELECT" and cur.type == T_COMMA:
                issues.append("comma right after SELECT at offset %d" % cur.start)
            elif prev.type == T_COMMA and cur.type == T_KEYWORD and cur.value.upper() in _CLAUSE_KEYWORDS \
                    and nxt is not None and nxt.type not in (T_COMMA, T_RPAREN):
                # a clause keyword right after a comma AND followed by real content is a
                # dangling list item ("a,b, FROM t"); if it is a bare list item itself
                # ("a,group,b" - a column named 'group') the next token is a comma/paren/end
                issues.append("dangling comma before '%s' at offset %d" % (cur.value, cur.start))
            elif pair == (T_RPAREN, T_LPAREN):
                issues.append("adjacent groups ')(' at offset %d" % cur.start)
            elif pair == (T_LPAREN, T_RPAREN) and (i < 2 or sig[i - 2].type in (T_OP, T_COMMA, T_LPAREN)):
                issues.append("empty parentheses at offset %d" % prev.start)
            elif cur.type == T_RPAREN and _isBinary(prev):
                issues.append("operator right before ')' at offset %d" % cur.start)
            elif prev.type == T_COMMA and curBinary:
                issues.append("operator right after ',' at offset %d" % cur.start)
            elif prev.type == T_LPAREN and curBinary:
                issues.append("operator right after '(' at offset %d" % cur.start)

        # -- doubled binary operators: '= =', 'AND AND' --------------------
        if prev is not None and _isBinary(prev) and curBinary:
            # allow a unary that legitimately follows (handled by NOT/~/sign)
            if not (cur.type == T_KEYWORD and cur.value.upper() == "NOT"):
                issues.append("doubled operator ('%s %s') at offset %d" % (prev.value, cur.value, prev.start))

        # -- stray un-lexable character ------------------------------------
        if cur.type == T_OTHER:
            issues.append("stray character '%s' at offset %d" % (cur.value, cur.start))

    # -- duplicated single-occurrence clause at one scope ('WHERE x WHERE y') --
    # WHERE/HAVING may appear at most once per SELECT scope; a second one at the
    # same paren-depth (no set operator or ';' resetting the SELECT in between)
    # is a structural impossibility no surrounding query can undo - subquery
    # clauses live at a deeper depth and reset on '(' / ')'.
    scopeSeen = [set()]
    for token in sig:
        if token.type == T_LPAREN:
            scopeSeen.append(set())
        elif token.type == T_RPAREN:
            if len(scopeSeen) > 1:
                scopeSeen.pop()
        elif token.type == T_SEMI:
            scopeSeen = [set()]
        elif token.type == T_KEYWORD:
            word = token.value.upper()
            if word in _SINGLE_CLAUSE_KEYWORDS:
                if word in scopeSeen[-1]:
                    issues.append("duplicate '%s' clause at offset %d" % (word, token.start))
                else:
                    scopeSeen[-1].add(word)
            elif word in _SET_OPERATORS:
                scopeSeen[-1].clear()

    return issues
