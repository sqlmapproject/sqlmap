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
    | (?P<%s>[A-Za-z_@$][A-Za-z0-9_@$]*)
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

_KEYWORDS_CACHE = None


class Token(object):
    __slots__ = ("type", "value", "start", "end")

    def __init__(self, type_, value, start, end):
        self.type = type_
        self.value = value
        self.start = start
        self.end = end


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
    """
    if not sql:
        return []

    if keywords is None:
        keywords = _keywords()

    issues = []
    tokens = tokenize(sql, keywords)

    # -- edge tolerance for unterminated strings ---------------------------
    # A trailing open quote at paren-depth 0 is a legitimate break-out. One
    # that opens *inside* a group (depth > 0) has swallowed a needed ')', i.e.
    # an odd quote count within an owned scope (the classic "users'" abomination).
    depth = 0
    for token in tokens:
        if token.type == T_LPAREN:
            depth += 1
        elif token.type == T_RPAREN:
            depth -= 1
        elif token.type == T_UNTERM:
            if depth > 0:
                issues.append("odd quote inside a parenthesized scope at offset %d" % token.start)
            break

    sig = _significant(tokens)

    for i in range(len(sig)):
        cur = sig[i]
        prev = sig[i - 1] if i > 0 else None
        nxt = sig[i + 1] if i + 1 < len(sig) else None

        # a keyword operator immediately followed by '(' is a function call
        # (e.g. the SQLite/MySQL LIKE(a, b) function), not a binary operator
        curIsFunc = cur.type == T_KEYWORD and nxt is not None and nxt.type == T_LPAREN
        curBinary = _isBinary(cur) and not curIsFunc

        # -- glued number/keyword boundary: '1UNION', '1AND' ---------------
        if cur.type == T_NUM and nxt is not None and nxt.start == cur.end and nxt.type in (T_IDENT, T_KEYWORD):
            issues.append("digit glued to a word ('%s%s') at offset %d" % (cur.value, nxt.value, cur.start))

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

    return issues
