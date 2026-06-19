#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.bigarray import BigArray
from lib.core.common import Backend
from lib.core.common import isNoneValue
from lib.core.common import singleTimeWarnMessage
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.compat import xrange
from lib.core.convert import getConsoleLength
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dicts import DUMP_REPLACEMENTS
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.settings import NULL
from lib.core.unescaper import unescaper
from lib.request import inject
from lib.utils.safe2bin import safechardecode

# back-end DBMSes whose dump table reference is schema/database-qualified (db.table).
# Note: for MSSQL the table identifier already carries its schema (e.g. dbo.users), so the
# plain db.table form yields the correct db.schema.table (e.g. [master].dbo.users).
KEYSET_SCHEMA_QUALIFIED = (DBMS.MYSQL, DBMS.PGSQL, DBMS.CRATEDB, DBMS.MSSQL, DBMS.H2, DBMS.HSQLDB)

def _tableRef(tbl):
    dbms = Backend.getIdentifiedDbms()
    if dbms in (DBMS.ORACLE,) and conf.db:
        return "%s.%s" % (conf.db.upper(), tbl.upper())
    if dbms in KEYSET_SCHEMA_QUALIFIED and conf.db:
        return "%s.%s" % (conf.db, tbl)
    return tbl

def keysetSupported():
    """
    Whether the back-end DBMS declares the keyset (seek) pagination queries and a
    cursor source (a physical row-id pseudo-column or a primary-key catalog lookup)
    """

    dumpNode = queries[Backend.getIdentifiedDbms()].dump_table
    return "keyset_next" in dumpNode.blind and ("rowid" in dumpNode.blind or "primary_key" in dumpNode)

def _integerCursor(tbl, cursor):
    """
    Whether every cursor column holds integer values, probed via MIN(col).

    Only integer keys are accepted: _embed() emits them as bare numeric literals, giving a
    numeric comparison that matches MIN/ORDER BY. String (and even decimal) keys would be
    escaped to a binary/hex literal whose order can differ from MIN's collation and silently
    skip rows, so they are rejected here and fall back to the OFFSET dump.
    """

    blind = queries[Backend.getIdentifiedDbms()].dump_table.blind
    ref = _tableRef(tbl)

    for column in cursor:
        query = agent.whereQuery(blind.keyset_first % (agent.preprocessField(tbl, column), ref))
        value = unArrayizeValue(inject.getValue(query))

        # empty/NULL MIN (e.g. empty table) is not disqualifying; the walk just yields no rows
        if not isNoneValue(value) and re.match(r"\A-?[0-9]+\Z", getUnicode(value).strip()) is None:
            return False

    return True

def resolveKeysetCursor(tbl, colList):
    """
    Returns the list of column(s) forming a stable, indexed cursor for keyset (seek)
    pagination of the table: a declared physical row-id pseudo-column when available,
    otherwise the indexed primary key (single or composite) resolved from the catalog.
    Returns None when neither applies or a key column is not part of the dumped columns.
    """

    if not keysetSupported():
        return None

    dumpNode = queries[Backend.getIdentifiedDbms()].dump_table

    # 1) a declared physical row-id pseudo-column (always unique + indexed where supported)
    if "rowid" in dumpNode.blind:
        return [dumpNode.blind.rowid]

    # 2) the indexed primary key (single-column, or composite when keyset_ordered is declared)
    pkNode = dumpNode.primary_key

    # Note: schema/table are string literals in the catalog lookups, so the unquoted
    # (identifier-unescaped) names are used (the dump queries keep the quoted form)
    unsafeDb = unsafeSQLIdentificatorNaming(conf.db)
    unsafeTbl = unsafeSQLIdentificatorNaming(tbl)

    # Note: no whereQuery() here - these are catalog (schema) lookups, so the data-row
    # filter from --where must not be appended to them
    query = pkNode.count % (unsafeDb, unsafeTbl)
    count = inject.getValue(query, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

    try:
        count = int(count)
    except (ValueError, TypeError):
        return None

    if count < 1:
        return None

    # composite keys require the row-value/ordered keyset form
    if count > 1 and "keyset_ordered" not in dumpNode.blind:
        return None

    cursor = []
    for index in xrange(count):
        query = pkNode.query % (unsafeDb, unsafeTbl, index)
        column = unArrayizeValue(inject.getValue(query))

        if not column:
            return None

        match = None
        for _ in colList:
            if _ and _.lower() == column.lower():
                match = _
                break

        if match is None:
            return None

        cursor.append(match)

    # restrict to integer cursors: a string key's escaped-literal comparison may order
    # differently than MIN/ORDER BY and silently skip rows (such keys fall back to OFFSET)
    if not _integerCursor(tbl, cursor):
        return None

    return cursor

def _lit(value):
    """
    Type-correct SQL literal for a cursor value: a bare numeric literal for numeric keys
    (so the index is still used and the comparison is numeric), otherwise the DBMS-escaped
    (e.g. 0x.. hex) form for string keys. Both forms are self-contained (no surrounding quotes).
    """

    if value is not None and re.match(r"\A-?[0-9]+\Z", value):
        return value
    return unescaper.escape(value, False)

def _embed(template, value, *fixed):
    """
    Fills a single-column keyset template whose trailing placeholder is the cursor value.
    """

    template = template.replace("'%s'", "%s")
    return template % (fixed + (_lit(value),))

def _dumpSingle(tbl, colList, count, cursor, tableRef, entries, lengths):
    blind = queries[Backend.getIdentifiedDbms()].dump_table.blind
    field = agent.preprocessField(tbl, cursor)

    if conf.limitStart and conf.limitStop:
        target = max(0, conf.limitStop - conf.limitStart + 1)
    elif conf.limitStop:
        target = conf.limitStop
    elif conf.limitStart:
        target = max(0, count - conf.limitStart + 1)
    else:
        target = count

    pivotValue = None

    # hybrid: a single OFFSET jump to seed the cursor just before --start, then pure keyset
    if conf.limitStart and conf.limitStart > 1 and "keyset_seed" in blind:
        query = agent.whereQuery(blind.keyset_seed % (field, tableRef, field, conf.limitStart - 2))
        seed = unArrayizeValue(inject.getValue(query))

        if isNoneValue(seed) or seed == NULL:
            return

        pivotValue = safechardecode(seed)

    produced = 0

    while produced < target:
        if pivotValue is None:
            query = blind.keyset_first % (field, tableRef)
        else:
            query = _embed(blind.keyset_next, pivotValue, field, tableRef, field)

        query = agent.whereQuery(query)
        value = unArrayizeValue(inject.getValue(query))

        if isNoneValue(value) or value == NULL:
            break

        value = safechardecode(value)

        # safety latch against a non-advancing cursor (e.g. encoding edge cases)
        if value == pivotValue:
            singleTimeWarnMessage("keyset cursor stopped advancing prematurely")
            break

        pivotValue = value

        for column in colList:
            if column == cursor:
                colValue = pivotValue
            else:
                query = _embed(blind.keyset_by, pivotValue, agent.preprocessField(tbl, column), tableRef, field)
                query = agent.whereQuery(query)
                colValue = unArrayizeValue(inject.getValue(query, dump=True))

            colValue = "" if isNoneValue(colValue) else colValue
            lengths[column] = max(lengths[column], getConsoleLength(DUMP_REPLACEMENTS.get(getUnicode(colValue), getUnicode(colValue))))
            entries[column].append(colValue)

        produced += 1

def _dumpComposite(tbl, colList, count, cursorCols, tableRef, entries, lengths):
    blind = queries[Backend.getIdentifiedDbms()].dump_table.blind
    fields = [agent.preprocessField(tbl, _) for _ in cursorCols]
    orderExpr = ','.join(fields)

    startSkip = (conf.limitStart - 1) if conf.limitStart else 0
    if conf.limitStart and conf.limitStop:
        target = max(0, conf.limitStop - conf.limitStart + 1)
    elif conf.limitStop:
        target = conf.limitStop
    elif conf.limitStart:
        target = max(0, count - conf.limitStart + 1)
    else:
        target = count

    prev = None
    produced = 0
    seen = 0

    while produced < target and seen < count:
        if prev is None:
            condition = "1=1"
        else:
            # ANSI row-value (tuple) comparison advances the composite cursor lexicographically
            condition = "(%s)>(%s)" % (orderExpr, ','.join(_lit(_) for _ in prev))

        tup = []
        for field in fields:
            query = agent.whereQuery(blind.keyset_ordered % (field, tableRef, condition, orderExpr))
            value = unArrayizeValue(inject.getValue(query))
            tup.append(None if isNoneValue(value) else safechardecode(value))

        if all(isNoneValue(_) for _ in tup):
            break

        if prev is not None and tup == prev:
            singleTimeWarnMessage("keyset cursor stopped advancing prematurely")
            break

        prev = tup
        seen += 1

        if seen <= startSkip:
            continue

        equals = " AND ".join("%s=%s" % (field, _lit(value)) for field, value in zip(fields, tup))

        for column in colList:
            if column in cursorCols:
                colValue = tup[cursorCols.index(column)]
            else:
                query = agent.whereQuery(blind.keyset_where % (agent.preprocessField(tbl, column), tableRef, equals))
                colValue = unArrayizeValue(inject.getValue(query, dump=True))

            colValue = "" if isNoneValue(colValue) else colValue
            lengths[column] = max(lengths[column], getConsoleLength(DUMP_REPLACEMENTS.get(getUnicode(colValue), getUnicode(colValue))))
            entries[column].append(colValue)

        produced += 1

def keysetDumpTable(tbl, colList, count, cursor):
    """
    Dumps a table one row at a time using keyset (seek) pagination on 'cursor' (a list of
    one or more indexed key columns): the next row is reached with a >/row-value comparison
    against the previous cursor (index range scan) and every other column is fetched with an
    exact equality on the cursor (index point seek), so no row is skipped via OFFSET and no
    per-row ORDER BY filesort is needed. A deep --start uses a single OFFSET "seed" jump
    (single-column cursors), after which the walk is pure keyset.
    """

    tableRef = _tableRef(tbl)
    lengths = {}
    entries = {}

    for column in colList:
        lengths[column] = 0
        entries[column] = BigArray()

    if len(cursor) == 1:
        _dumpSingle(tbl, colList, count, cursor[0], tableRef, entries, lengths)
    else:
        _dumpComposite(tbl, colList, count, cursor, tableRef, entries, lengths)

    debugMsg = "keyset pagination retrieved %d row(s) for table '%s'" % (len(entries[colList[0]]) if colList and colList[0] in entries else 0, unsafeSQLIdentificatorNaming(tbl))
    logger.debug(debugMsg)

    return entries, lengths
