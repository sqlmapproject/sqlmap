#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from .engine import Esperanto
from .records import OracleUndecided


def buildHandler():
    """Build the sqlmap dbmsHandler that drives enumeration through this engine when
    the back-end cannot be (or should not be) fingerprinted. sqlmap-core imports are
    deferred here so the engine above stays dependency-free for standalone use.

    The user still commands *what* to retrieve (--banner / --tables / --dump / ...);
    esperanto only works out *how* on a dialect it discovers from scratch, and every
    probe rides sqlmap's own boolean inference (request / comparison / WAF stack)."""
    from lib.core.data import conf
    from lib.core.data import kb
    from lib.core.data import logger
    from lib.core.enums import CHARSET_TYPE
    from lib.core.enums import EXPECTED
    from lib.core.exception import SqlmapDataException
    from lib.request.inject import checkBooleanExpression
    from lib.request.inject import getValue
    from plugins.generic.enumeration import Enumeration
    from plugins.generic.misc import Miscellaneous

    # boolean-blind-only oracle (no inband UNION marker): whole-page true/false, so a
    # reflective target that filters out the reflected marker can't defeat it
    def _blindOracle(condition):
        return getValue(condition, expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY,
                        suppressOutput=True, union=False, error=False, time=False)

    class _EsperantoHandler(Enumeration, Miscellaneous):
        def __init__(self):
            Enumeration.__init__(self)
            Miscellaneous.__init__(self)
            self._esp = None
            self._identCache = {}       # current user/db: fetch (and announce) once
            self._colCache = {}         # (db, table) -> ordered column names, so a dump
                                        # reuses what --columns already enumerated
            self._scopeCache = {}       # table -> resolved schema (see _scopeFor)

        def _engine(self):
            if self._esp is None:
                # esperanto is a PURE boolean-oracle engine: every probe is one true/false
                # question, so it gains nothing from UNION/error inband extraction - while
                # those need a concatenated marker whose generic form is CONCAT() when the
                # backend is unidentified (agent.py), and CONCAT() does not exist on SQLite/
                # Firebird/Oracle (they use ||) so every such probe errors. so PREFER the
                # boolean-blind technique: no marker, no concatenation, whole-page true/false,
                # works everywhere. only fall back to whatever-technique-is-available if the
                # target has no usable boolean-blind vector. _ask decides what an undecidable
                # probe MEANS by context (skip a candidate rung vs degrade a data read loudly).
                esp = Esperanto(_blindOracle, retries=2)
                logger.info("Esperanto is discovering the back-end SQL dialect (agnostic mode, boolean-blind)")
                try:
                    esp.discover()
                except RuntimeError:
                    # no usable boolean-blind vector on this target - retry with any technique
                    # sqlmap detected (UNION/error/time); may hit the CONCAT limitation above
                    esp = Esperanto(lambda condition: checkBooleanExpression(condition), retries=2)
                    logger.info("Esperanto retrying discovery via any available inference technique")
                    try:
                        esp.discover()
                    except RuntimeError as ex:
                        # genuinely unusable (unstable target, or no substring/pattern
                        # primitive) - stop cleanly instead of surfacing an internal traceback
                        raise SqlmapDataException("Esperanto could not establish a reliable extraction oracle on this target (%s)" % ex)
                logger.info("Esperanto dialect verdict: %s" % (esp.identify().get("product") or "unknown"))
                esp._progress = lambda value: logger.info("retrieved: %s" % value)  # live feedback
                for note in esp.dialect.notes:          # surface degradations LOUDLY (never silent)
                    logger.warning("Esperanto: %s" % note)
                self._esp = esp
            return self._esp

        def _scopeDb(self):
            # the database to scope table/column lookups to: -D if given, else the
            # current one. WITHOUT this, a same-named table in another schema (e.g.
            # information_schema.USERS vs shop.users) merges columns and breaks dump.
            return conf.db or self.getCurrentDb()

        def _scopeFor(self, table):
            # scope for a SPECIFIC table: -D wins; else the current schema IF the table
            # is there; else the schema the table actually lives in (PG-family: tables
            # often sit in 'public' while current_schema is the login user's own schema).
            if conf.db:
                return conf.db
            if table in self._scopeCache:
                return self._scopeCache[table]
            esp = self._engine()
            cur = self.getCurrentDb()
            scope = cur if (cur and esp.hasTable(table, cur)) else (esp.tableSchema(table) or cur)
            self._scopeCache[table] = scope
            return scope

        def _db(self):
            return self._scopeDb() or "<current>"

        def getFingerprint(self):
            # concise fingerprint only; the version banner is shown for --banner, not
            # printed unbidden on every run (and not re-extracted here)
            product = self._engine().identify().get("product") or "unknown"
            return "back-end DBMS: %s (via Esperanto DBMS-agnostic engine)" % product

        def getBanner(self):
            # the ONLY path that blind-reads the full version string (expensive); the
            # fingerprint/product naming never does
            logger.info("fetching banner")
            kb.data.banner = self._engine().banner()
            return kb.data.banner

        def getCurrentUser(self):
            if "user" not in self._identCache:
                expr = self._engine().dialect.identity.get("user")
                if expr:
                    logger.info("fetching current user")
                self._identCache["user"] = self._safeExtract(expr) if expr else None
            kb.data.currentUser = self._identCache["user"]
            return kb.data.currentUser

        def getCurrentDb(self):
            # called repeatedly to scope tables/columns/dump -> fetch and announce once
            if "db" not in self._identCache:
                expr = self._engine().dialect.identity.get("database")
                if expr:
                    logger.info("fetching current database")
                self._identCache["db"] = self._safeExtract(expr) if expr else None
            kb.data.currentDb = self._identCache["db"]
            return kb.data.currentDb

        def _safeExtract(self, expr):
            try:
                return self._esp.extract(expr)
            except OracleUndecided:
                logger.warning("Esperanto could not retrieve %s (oracle undecided)" % expr)
                return None

        def isDba(self, user=None):
            kb.data.isDba = False           # no privilege claim the oracle cannot prove
            return kb.data.isDba

        def getDbs(self):
            logger.info("fetching database names")
            kb.data.cachedDbs = self._engine().enumerate("database", limit=(conf.limitStop or 50)) or []
            return kb.data.cachedDbs

        def getTables(self, bruteForce=None):
            # scope to the requested database (-D) or the current one, so the listing
            # isn't polluted with every schema's tables (e.g. information_schema)
            db = conf.db or self.getCurrentDb()
            lim = conf.limitStop or 100
            names = self._engine().enumerate("table", limit=lim, schema=db) or []
            if not names and not conf.db and db != "public":
                # current schema empty (PG-family: login-user schema) -> tables usually
                # live in 'public'; broaden rather than report nothing
                pub = self._engine().enumerate("table", limit=lim, schema="public") or []
                if pub:
                    names, db = pub, "public"
            infoMsg = "fetching tables"
            if db:
                infoMsg += " for database '%s'" % db
            logger.info(infoMsg)
            kb.data.cachedTables = {db or "<current>": names}
            return kb.data.cachedTables

        def getColumns(self, onlyColNames=False, colTuple=None, bruteForce=None, dumpMode=False):
            if not conf.tbl:
                logger.error("Esperanto needs a table (-T) to enumerate columns")
                return {}
            db = self._scopeFor(conf.tbl)
            infoMsg = "fetching columns for table '%s'" % conf.tbl
            if db:
                infoMsg += " in database '%s'" % db
            logger.info(infoMsg)
            names = self._engine().columns(conf.tbl, schema=db) or []
            self._colCache[(db, conf.tbl)] = names       # let a following dump reuse these
            kb.data.cachedColumns = {db or "<current>": {conf.tbl: dict((n, None) for n in names)}}
            return kb.data.cachedColumns

        def getSchema(self):
            esp = self._engine()
            db = self._scopeDb()
            schema = {}
            for table in (self.getTables().get(self._db()) or []):
                schema[table] = dict((n, None) for n in (esp.columns(table, schema=db) or []))
            kb.data.cachedColumns = {self._db(): schema}
            return kb.data.cachedColumns

        def dumpTable(self, foundData=None):
            if not conf.tbl:
                logger.error("Esperanto needs a table (-T) to dump")
                return
            db = self._scopeFor(conf.tbl)
            cols = [c.strip() for c in conf.col.split(",")] if conf.col else None
            if cols is None:
                cols = self._colCache.get((db, conf.tbl))    # reuse --columns' result; don't re-walk
            infoMsg = "fetching entries"
            if cols:
                infoMsg += " of column(s) '%s'" % ", ".join(cols)
            infoMsg += " for table '%s'" % conf.tbl
            if db:
                infoMsg += " in database '%s'" % db
            logger.info(infoMsg)
            result = self._engine().dump(conf.tbl, columns=cols, schema=db, limit=(conf.limitStop or 10))
            if not result or not result["columns"]:
                logger.error("Esperanto could not dump table '%s'" % conf.tbl)
                return
            table_data = {}
            for i, name in enumerate(result["columns"]):
                values = [("NULL" if row[i] is None else row[i]) for row in result["rows"]]
                width = max([len(name)] + [len(v) for v in values]) if values else len(name)
                table_data[name] = {"length": width, "values": values}
            table_data["__infos__"] = {"count": len(result["rows"]), "table": conf.tbl, "db": self._db()}
            if not result["complete"]:
                logger.warning("Esperanto dump of '%s' may be incomplete" % conf.tbl)
            kb.data.dumpedTable = table_data
            conf.dumper.dbTableValues(kb.data.dumpedTable)

    return _EsperantoHandler()
