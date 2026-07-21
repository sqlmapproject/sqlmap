#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Capability atlas: the candidate SQL forms Esperanto tries (best-first) to discover a
dialect blind, mined from data/xml/queries.xml across the supported DBMSes. Data only,
no logic. Each table is (name, template, ...); templates use str.format fields such as
{expr}/{a}/{b}/{code}/{col}/{x}. Source is pure ASCII - any non-ASCII character is
written as a \\uXXXX escape so it is always obvious which code point is meant.
"""

from __future__ import print_function

import binascii


def _unhexlify(value):
    """Strict py2/3 hex decode - rejects non-hex/odd-length rather than cleaning it."""
    if isinstance(value, type(u"")):
        value = value.encode("ascii")
    return binascii.unhexlify(value)


def _isSingleUnicodeScalar(value):
    """True for exactly one Unicode scalar (incl. a py2 narrow-build surrogate pair)."""
    if len(value) == 1:
        return True
    return (len(value) == 2 and 0xD800 <= ord(value[0]) <= 0xDBFF and
            0xDC00 <= ord(value[1]) <= 0xDFFF)


# string concatenation of {a} and {b} (operator or function form)
_CONCAT = (
    ("pipes", "({a})||({b})"),          # || : 26/31 DBMSes (ANSI)
    ("concat", "CONCAT({a},{b})"),      # MySQL/MaxDB/HSQLDB
    ("plus", "({a})+({b})"),            # MSSQL/Sybase
    ("amp", "({a})&({b})"),             # MS Access
)


# 1-based substring: {len} characters of {expr} starting at {pos}
_SUBSTRING = (
    ("SUBSTR", "SUBSTR(({expr}),{pos},{len})"),
    ("SUBSTRING", "SUBSTRING(({expr}),{pos},{len})"),
    ("MID", "MID(({expr}),{pos},{len})"),
    ("SUBSTRING_FROM", "SUBSTRING(({expr}) FROM {pos} FOR {len})"),
    ("SUBSTRC", "SUBSTRC(({expr}),{pos},{len})"),
    ("substring_lc", "substring(({expr}),{pos},{len})"),
    # LEFT/RIGHT composition, a fallback rung for dialects/filters exposing LEFT+RIGHT
    # but not SUBSTR/SUBSTRING/MID. NOTE: this identity is exact only for len<=1 (which
    # is ALL esperanto ever asks - every _sub() call reads one char), where it reduces to
    # RIGHT(LEFT(x,pos),1). For len>1 past the string end it over-returns; the general
    # fix needs LEN(x), which would defeat this rung's whole purpose (no length fn), so
    # it is deliberately kept length-free and len=1-scoped.
    ("left_right", "RIGHT(LEFT(({expr}),({pos})+({len})-1),{len})"),
)


# CHARACTER count of {expr} (byte-count functions live in _BYTELEN, not here)
_LENGTH = (
    ("CHAR_LENGTH", "CHAR_LENGTH({expr})"),
    ("LENGTH", "LENGTH({expr})"),
    ("LEN", "LEN({expr})"),
    ("length_lc", "length({expr})"),
)


# single char {expr} -> its integer code point
_CHARCODE = (
    ("ASCII", "ASCII({expr})"),
    ("UNICODE", "UNICODE({expr})"),
    ("ORD", "ORD({expr})"),
    ("CODEPOINT", "CODEPOINT({expr})"),
    ("UNICODE_VAL", "UNICODE_VAL({expr})"),                             # Firebird (code point; ASCII_VAL below errors >255)
    ("ASCII_VAL", "ASCII_VAL({expr})"),
    ("ASCW", "ASCW({expr})"),
    ("UNICODE_CODE", "UNICODE_CODE({expr})"),
    ("TO_CODE_POINTS", "TO_CODE_POINTS({expr})[SAFE_OFFSET(0)]"),        # BigQuery/Spanner (array-indexed)
)


# integer {code} -> single char (lets extraction build literals without quoting)
_CHARFROM = (
    ("CHAR", "CHAR({code})"),
    ("CHR", "CHR({code})"),
    ("NCHAR", "NCHAR({code})"),
    ("UNICODE_CHAR", "UNICODE_CHAR({code})"),                           # Firebird (code point; pairs with UNICODE_VAL)
    ("ASCII_CHAR", "ASCII_CHAR({code})"),                               # Firebird (0-255)
)


# {expr} -> uppercase, prefixless (no 0x/0h) HEX of its bytes (collation-independent; recovers case)
_HEXFN = (
    ("HEX", "UPPER(HEX({expr}))"),                                       # MySQL/MariaDB/TiDB/SQLite/DB2/MaxDB/Cubrid/ClickHouse/Doris/StarRocks/Spark/Hive
    ("RAWTOHEX_RAW", "UPPER(RAWTOHEX(UTL_RAW.CAST_TO_RAW({expr})))"),    # Oracle
    ("RAWTOHEX", "UPPER(RAWTOHEX({expr}))"),                             # H2 / HSQLDB (yields UTF-16 hex, e.g. 'q'->'0071')
    ("ENCODE", "UPPER(ENCODE(CONVERT_TO(({expr})::text,'UTF8'),'HEX'))"),# PostgreSQL/CockroachDB/CrateDB
    ("mssql_convert", "UPPER(CONVERT(VARCHAR(MAX),CONVERT(VARBINARY(MAX),CONVERT(NVARCHAR(MAX),{expr})),2))"),  # MSSQL/Azure SQL: normalize to NVARCHAR so the bytes are ALWAYS UTF-16LE (CAST-to-VARBINARY of a varchar is 1-byte, of an nvarchar 2-byte - mixing the two mis-decodes); MAX = don't truncate
    ("BINTOSTR", "UPPER(BINTOSTR(CONVERT(VARBINARY,{expr})))"),          # Sybase
    ("HEX_ENCODE", "UPPER(HEX_ENCODE({expr}))"),                         # Snowflake/Altibase (Firebird needs a VARBINARY cast)
    ("BINTOHEX", "UPPER(BINTOHEX(TO_BINARY({expr})))"),                 # SAP HANA
    ("TO_HEX_VARBINARY", "UPPER(TO_HEX(CAST({expr} AS VARBINARY)))"),   # Presto/Vertica
    ("TO_HEX_BYTES", "UPPER(TO_HEX(CAST({expr} AS BYTES)))"),           # BigQuery/Spanner
)


# uppercase hex alphabet the nibble reader walks over
_HEXDIGITS = "0123456789ABCDEF"


# cap on a single char's hex length (UTF-32 = 8 bytes = 16 nibbles)
_MAX_HEX_CHAR_NIBBLES = 16


# hex encodings of 'q' (0x71) -> the text codec that decodes them; distinguishes
# single-byte (utf-8/ascii) from UTF-16 BE/LE so the dump decoder reads the right one
_HEX_Q_ENCODINGS = (("71", "utf-8"), ("0071", "utf-16-be"), ("7100", "utf-16-le"))


# scalar expressions that yield the back-end's DECLARED character set NAME, tried in turn -
# the strongest encoding signal there is (the DB tells us its own charset), and read once. A
# wrong-family probe errors -> reported False -> skipped, so the first that resolves is the one.
_CHARSET_PROBES = (
    "@@character_set_connection",                                           # MySQL/MariaDB/TiDB: the charset
                                                                            # CAST(x AS CHAR) outputs (what the
                                                                            # framed dump hexes), NOT @@character_set_database
    "current_setting('server_encoding')",                                   # PostgreSQL / Cockroach / Crate
    "(SELECT value FROM nls_database_parameters WHERE parameter='NLS_CHARACTERSET')",  # Oracle
    "CONVERT(VARCHAR(64),COLLATIONPROPERTY(CONVERT(NVARCHAR(128),SERVERPROPERTY('Collation')),'CodePage'))",  # SQL Server -> code page number
)


# declared charset NAME (normalized: lowercased, non-alphanumerics stripped) -> Python codec.
# Encodes the vendor QUIRKS that make byte-level guessing wrong: MySQL "latin1" is really
# Windows-1252, Oracle "WE8MSWIN1252"/PG "WIN1252" too; only "iso-8859-1"-named sets are true
# Latin-1. This is where reading the DB's own answer beats statistical detection.
_CHARSET_CODEC = {
    "utf8": "utf-8", "utf8mb4": "utf-8", "utf8mb3": "utf-8", "al32utf8": "utf-8",
    "unicode": "utf-8", "utf8unicodeci": "utf-8", "65001": "utf-8",
    "utf16": "utf-16", "utf16le": "utf-16-le", "utf16be": "utf-16-be", "al16utf16": "utf-16-be", "ucs2": "utf-16-be",
    "latin1": "cp1252",                                                     # MySQL 'latin1' == Windows-1252
    "cp1252": "cp1252", "windows1252": "cp1252", "we8mswin1252": "cp1252", "win1252": "cp1252", "1252": "cp1252",
    "iso88591": "latin-1", "we8iso8859p1": "latin-1", "88591": "latin-1", "28591": "latin-1",
    "iso885915": "iso-8859-15", "latin9": "iso-8859-15", "we8iso8859p15": "iso-8859-15",
    "cp1251": "cp1251", "windows1251": "cp1251", "win1251": "cp1251", "cl8mswin1251": "cp1251", "1251": "cp1251",
    "cp1250": "cp1250", "windows1250": "cp1250", "ee8mswin1250": "cp1250", "1250": "cp1250",
    "gbk": "gbk", "gb2312": "gbk", "zhs16gbk": "gbk", "936": "gbk", "gb18030": "gb18030",
    "big5": "big5", "zht16big5": "big5", "950": "big5",
    "sjis": "shift_jis", "shiftjis": "shift_jis", "cp932": "shift_jis", "ja16sjis": "shift_jis", "932": "shift_jis",
    "euckr": "euc-kr", "ko16ksc5601": "euc-kr", "51949": "euc-kr",
    "eucjp": "euc-jp", "ujis": "euc-jp", "ja16euc": "euc-jp",
    "koi8r": "koi8-r", "cl8koi8r": "koi8-r",
    "ascii": "ascii", "usascii": "ascii", "us7ascii": "ascii",
}


def _charsetCodec(name):
    """Map a declared charset NAME (or code-page number) to a Python codec, or None if unknown.
    Trailing collation qualifiers (MySQL `utf8mb4_general_ci`) are stripped progressively."""
    import re as _re
    key = _re.sub(r"[^a-z0-9]", "", (name or "").lower())
    while key:
        if key in _CHARSET_CODEC:
            return _CHARSET_CODEC[key]
        key = key[:-1]                          # peel trailing collation suffix (utf8mb4generalci -> ... -> utf8mb4)
    return None


# the only code points a hex-framed dump payload can contain (hex digits + N/V markers
# + the length-frame ':'/';' + the legacy ',' delimiter); lets that value extract via a tiny
# bisection alphabet. MUST include ':' and ';' or the length-framed grammar's chars fall
# outside the alphabet -> whole-value verify fails -> a costly full-hex re-extraction.
_HEX_PAYLOAD_CODES = sorted(set(ord(c) for c in ",:;0123456789ABCDEFNV"))


# force a byte-ordered, case/accent-sensitive comparison of {x} even where the default
# collation is case-insensitive (SQL Server, MySQL _ci) or locale-linguistic (PostgreSQL)
_BINWRAP = (
    ("collate_c", "({x}) COLLATE \"C\""),                    # PostgreSQL/Redshift/Greenplum/CockroachDB/Vertica
    ("collate_bin2", "({x}) COLLATE Latin1_General_BIN2"),   # SQL Server/Sybase ASE
    ("collate_mysqlbin", "({x}) COLLATE utf8mb4_bin"),       # MySQL/MariaDB/TiDB/Doris/StarRocks
    ("binary_op", "BINARY ({x})"),                            # MySQL (operator form)
    ("cast_bytea", "CAST(({x}) AS bytea)"),                  # PostgreSQL family
    ("cast_varbinary", "CAST(({x}) AS VARBINARY(8000))"),    # SQL Server/DB2
    ("cast_blob", "CAST(({x}) AS BLOB)"),                    # SQLite/Firebird/Derby
    ("nlssort", "NLSSORT(({x}),'NLS_SORT=BINARY')"),         # Oracle
    ("raw", "UTL_RAW.CAST_TO_RAW({x})"),                     # Oracle (RAW bytewise)
)


# aggregate column {col} across all rows into ONE delimited string (one-shot bulk pull)
_BULK_AGG = (
    ("group_concat", "GROUP_CONCAT({col})"),                                 # MySQL/MariaDB/SQLite/H2/HSQLDB/CUBRID/Doris/StarRocks
    ("string_agg", "STRING_AGG(CAST({col} AS VARCHAR(4000)),',')"),          # PostgreSQL/SQLServer2017+/Snowflake/Spanner/HANA/DuckDB/Cockroach/Greenplum/BigQuery
    ("listagg_ovf", "LISTAGG({col},',' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY {col})"),  # Oracle 12.2+/graceful
    ("listagg", "LISTAGG({col},',') WITHIN GROUP (ORDER BY {col})"),         # Oracle/DB2/Vertica/Redshift/Altibase
    ("array_agg", "ARRAY_TO_STRING(ARRAY_AGG({col}),',')"),                  # PostgreSQL/Presto/Trino/CrateDB
    ("list_fb", "LIST({col})"),                                             # Firebird (returns BLOB)
    ("xmlagg", "RTRIM(XMLAGG(XMLELEMENT(NAME \"E\",{col},',').EXTRACT('//text()')))"),  # Teradata/DB2 (SQL/XML NAME kw)
)


# FROM-suffix a bare scalar SELECT needs (bare = none); a non-bare match fingerprints the family
_DUAL = (
    ("bare", ""),                                   # MySQL/PostgreSQL/SQLite/SQLServer/Snowflake/...
    ("DUAL", " FROM DUAL"),                          # Oracle / SAP MaxDB / Altibase / CUBRID
    ("SYSIBM.SYSDUMMY1", " FROM SYSIBM.SYSDUMMY1"),  # IBM Db2 / Apache Derby
    ("RDB$DATABASE", " FROM RDB$DATABASE"),          # Firebird
    ("DUMMY", " FROM DUMMY"),                        # SAP HANA
    ("SYSMASTER:SYSDUAL", " FROM SYSMASTER:SYSDUAL"),  # Informix
    ("VALUES", " FROM (VALUES(1)) t"),               # HSQLDB / standard
    ("system.onerow", " FROM system.onerow"),        # Mimer SQL
)


# which product(s) a non-bare _DUAL match implies (for the identify() evidence trail)
_DUAL_IMPLIES = {
    "DUAL": "Oracle / MaxDB / Altibase / CUBRID",
    "SYSIBM.SYSDUMMY1": "IBM Db2 / Apache Derby",
    "RDB$DATABASE": "Firebird",
    "DUMMY": "SAP HANA",
    "SYSMASTER:SYSDUAL": "Informix",
    "VALUES": "HSQLDB / SQL-standard",
    "system.onerow": "Mimer SQL",
}


# version-banner probes: (label, expr, product, implies_product). engine-specific first;
# implies_product=False marks generic banners where only the banner TEXT names the product
_BANNERS = (
    ("H2VERSION()", "H2VERSION()", "H2", True),
    ("SQLITE_VERSION()", "SQLITE_VERSION()", "SQLite", True),
    ("DATABASE_VERSION()", "DATABASE_VERSION()", "HSQLDB", True),
    ("CURRENT_VERSION()", "CURRENT_VERSION()", "Snowflake", True),
    ("product_component_version", "(SELECT version FROM product_component_version WHERE ROWNUM=1)", "Oracle", True),  # low-priv Oracle
    ("v$version", "(SELECT banner FROM v$version WHERE ROWNUM=1)", "Oracle", True),   # needs SELECT_CATALOG_ROLE
    ("rdb$get_context", "(SELECT rdb$get_context('SYSTEM','ENGINE_VERSION') FROM rdb$database)", "Firebird", True),
    ("SYS.M_DATABASE", "(SELECT VERSION FROM SYS.M_DATABASE)", "SAP HANA", True),
    ("$ZVERSION", "$ZVERSION", "InterSystems Cache/IRIS", True),
    ("SYS.SYSTABLES", "(SELECT DBINFO('VERSION','FULL') FROM systables WHERE tabid=1)", "Informix", True),
    ("@@VERSION", "@@VERSION", None, False),
    ("VERSION()", "VERSION()", None, False),
    ("version()", "version()", None, False),
)


# product names searched for INSIDE a banner string; forks listed BEFORE their parents
# (e.g. MariaDB before MySQL) so the more specific name wins
_BANNER_KEYWORDS = (
    "Microsoft SQL Server",
    "CockroachDB", "Redshift", "Greenplum", "Vertica", "PostgreSQL",
    "TiDB", "Percona", "MariaDB", "MySQL",
    "Oracle", "SQLite", "SAP HANA", "DB2", "Firebird", "Snowflake",
    "Presto", "Trino", "ClickHouse", "H2", "HSQLDB", "MonetDB", "CrateDB", "Informix",
)


# BYTE-length of {expr} (distinct from _LENGTH's character count; for binary-safe sizing)
_BYTELEN = (
    ("OCTET_LENGTH", "OCTET_LENGTH({expr})"),
    ("DATALENGTH", "DATALENGTH({expr})"),
    ("LENGTHB", "LENGTHB({expr})"),
)


# cast an arbitrary scalar (int/date/binary) {expr} to text so it can be substringed
# PREFER UNBOUNDED casts - a bounded VARCHAR(4000) passes discovery (short test value) but
# SILENTLY TRUNCATES a longer value before it is framed/hexed, corrupting a dump that still
# looks complete. Unbounded forms are tried first; the discovery probe's exact-length check
# rejects a CHAR(1)-style truncating cast, so listing CAST(AS CHAR) is safe (MySQL: unbounded;
# elsewhere: CHAR(1) -> length 3 check fails -> skipped). Oracle VARCHAR2 has a hard 4000 cap,
# so a >4000 value there is caught by per-cell source verification in dump(), not here.
_TEXTCAST = (
    ("cast_text", "CAST(({expr}) AS TEXT)"),                 # PostgreSQL/SQLite/... UNBOUNDED
    ("cast_char", "CAST(({expr}) AS CHAR)"),                 # MySQL/MariaDB UNBOUNDED (bare CHAR)
    ("cast_nvarchar_max", "CAST(({expr}) AS NVARCHAR(MAX))"),# SQL Server UNBOUNDED
    ("cast_varchar_max", "CAST(({expr}) AS VARCHAR(MAX))"),  # SQL Server UNBOUNDED (non-Unicode)
    ("cast_string", "CAST(({expr}) AS STRING)"),             # BigQuery/Spark UNBOUNDED
    ("cast_varchar", "CAST(({expr}) AS VARCHAR(4000))"),     # bounded fallbacks (short values only)
    ("cast_varchar2", "CAST(({expr}) AS VARCHAR2(4000))"),   # Oracle (hard 4000 limit)
    ("to_char", "TO_CHAR({expr})"),
    ("convert_varchar", "CONVERT(VARCHAR(4000),({expr}))"),
    ("cast_nvarchar", "CAST(({expr}) AS NVARCHAR(4000))"),
)


# substitute {fallback} when {expr} IS NULL
_COALESCE = (
    ("COALESCE", "COALESCE({expr},{fallback})"),
    ("IFNULL", "IFNULL({expr},{fallback})"),
    ("NVL", "NVL({expr},{fallback})"),
    ("ISNULL", "ISNULL({expr},{fallback})"),
    ("case", "CASE WHEN ({expr}) IS NULL THEN {fallback} ELSE ({expr}) END"),
)


# expressions that yield the current user / database-or-schema / version, per kind
_IDENTITY = {
    "user": (
        "CURRENT_USER", "CURRENT_USER()", "USER", "USER()", "SYSTEM_USER",
        "SUSER_NAME()", "USER_NAME()", "USERNAME()", "currentUser()",
    ),
    # the CURRENT namespace used to scope table/column lookups. prefer the SCHEMA
    # functions: on schema-based engines (h2/hsqldb/derby/pg) the catalog's scope
    # column is the SCHEMA (PUBLIC/APP/public), NOT the database name (h2 DATABASE()
    # is 'TEST' but its tables live in schema 'PUBLIC'). where db==schema (MySQL),
    # SCHEMA() returns the same value, so nothing regresses.
    "database": (
        "CURRENT_SCHEMA()", "current_schema()", "CURRENT_SCHEMA", "current_schema",
        "SCHEMA_NAME()", "SCHEMA()", "CURRENT SCHEMA", "DATABASE()", "DB_NAME()", "currentDatabase()",
    ),   # SCHEMA_NAME() = SQL Server's schema (dbo), so tables scope+qualify as schema.table (e.g. "dbo"."users"); its DB_NAME() ('master') is NOT a valid 2-part schema prefix
    "version": (
        "VERSION()", "version()", "@@VERSION", "SQLITE_VERSION()",
        "DATABASE_VERSION()", "H2VERSION()", "CURRENT_VERSION()",
        "(SELECT banner FROM v$version WHERE ROWNUM=1)",     # Oracle
        "(SELECT version FROM v$instance)",                  # Oracle alt
    ),
}


# table catalogs: (probe-name, family, {kind: (name_col, source, filter)}). the first
# whose COUNT(*) succeeds both enables enumeration and fingerprints the DBMS family
_CATALOGS = (
    ("sqlite_master", "SQLite",
     {"table": ("tbl_name", "sqlite_master", "type='table'")}),
    ("SYS.ALL_TABLES", "Oracle",       # exclude recyclebin objects (dropped tables linger as
     {"table": ("TABLE_NAME", "SYS.ALL_TABLES", "TABLE_NAME NOT LIKE 'BIN$%'"),   # BIN$... in ALL_TABLES) - idea from SchemaCrawler
      "schema": ("OWNER", "SYS.ALL_TABLES", None)}),
    ("sys.summits", "CrateDB",       # CrateDB signature table (mountain summits); MUST precede
     {"table": ("table_name", "information_schema.tables", None),   # pg_catalog (CrateDB is PG-wire -> was mis-ID'd PostgreSQL + collided with its system `users`)
      "schema": ("table_schema", "information_schema.tables", None)}),
    ("pg_catalog.pg_tables", "PostgreSQL-family",
     {"table": ("tablename", "pg_catalog.pg_tables", None),
      "schema": ("schemaname", "pg_catalog.pg_tables", None)}),
    ("master..sysdatabases", "MSSQL/Sybase",
     {"database": ("name", "master..sysdatabases", None),
      "schema": ("name", "sys.schemas", None),
      "table": ("name", "sys.tables", None)}),
    ("RDB$RELATIONS", "Firebird",
     {"table": ("TRIM(RDB$RELATION_NAME)", "RDB$RELATIONS", "RDB$SYSTEM_FLAG=0")}),  # user tables only; TRIM the CHAR(63) padding
    ("syscat.tables", "IBM DB2",
     {"table": ("tabname", "syscat.tables", None)}),
    ("sys._tables", "MonetDB",       # MonetDB-unique (underscore); MUST precede SYS.OBJECTS,
     {"table": ("name", "sys._tables", "system=false")}),   # which MonetDB ALSO has -> was mis-ID'd as SAP HANA
    ("SYS.OBJECTS", "SAP HANA",
     {"table": ("OBJECT_NAME", "SYS.OBJECTS", "OBJECT_TYPE='TABLE'")}),
    ("SYS.SYSTABLES", "Apache Derby",
     {"table": ("TABLENAME", "SYS.SYSTABLES", "TABLETYPE='T'")}),   # Derby native catalog (user tables)
    ("SYSIBM.SYSTABLES", "DB2/Derby",
     {"table": ("NAME", "SYSIBM.SYSTABLES", None)}),
    ("db_class", "CUBRID",           # CUBRID-unique catalog (object-oriented heritage);
     {"table": ("class_name", "db_class", "is_system_class='NO'")}),   # else it matched nothing -> brute-forced blindly + went unnamed
    ("systables", "Informix",        # bare `systables` is Informix-specific (others are SYS./SYSIBM.-qualified);
     {"table": ("tabname", "systables", "tabid>=100 AND tabtype='T'")}),   # tabid>=100 = user objects, tabtype='T' = base tables
    ("system.tables", "ClickHouse",  # precede INFORMATION_SCHEMA (CH has both); scope to the
     {"table": ("name", "system.tables", "database=currentDatabase()")}),   # current db so its own system.* tables (incl a `users`!) don't pollute
    ("INFORMATION_SCHEMA.TABLES", "ANSI (MySQL/MSSQL/PG/...)",
     {"table": ("table_name", "INFORMATION_SCHEMA.TABLES", None),
      "schema": ("table_schema", "INFORMATION_SCHEMA.TABLES", None)}),
)


# per-catalog column enumeration: (name_col, source, filter) where filter has one %s
# for the (literal) table name; matched by the catalog chosen above
# (name_col, source, where-template-with-one-%s, ordinal_col); the 4th column is the
# catalog's declared column position, used to return columns in DEFINITION order (else
# they come out alphabetical); a wrong/absent one just degrades to alphabetical
_COLUMN_SPECS = {
    "sqlite_master": ("name", "pragma_table_info(%s)", None, "cid"),
    "SYS.ALL_TABLES": ("column_name", "SYS.ALL_TAB_COLUMNS", "table_name=%s", "COLUMN_ID", "OWNER"),  # Oracle scopes by OWNER, not table_schema
    "pg_catalog.pg_tables": ("column_name", "information_schema.columns", "table_name=%s", "ordinal_position"),
    "sys.summits": ("column_name", "information_schema.columns", "table_name=%s", "ordinal_position"),  # CrateDB (schema-scoped by columns())
    "master..sysdatabases": ("name", "syscolumns", "id=OBJECT_ID(%s)", "colid"),
    "RDB$RELATIONS": ("TRIM(RDB$FIELD_NAME)", "RDB$RELATION_FIELDS", "RDB$RELATION_NAME=%s", "RDB$FIELD_POSITION"),  # TRIM the CHAR padding
    "syscat.tables": ("colname", "syscat.columns", "tabname=%s", "colno"),
    "db_class": ("attr_name", "db_attribute", "class_name=%s", "def_order"),  # CUBRID
    "systables": ("colname", "syscolumns", "tabid=(SELECT tabid FROM systables WHERE tabname=%s)", "colno"),  # Informix
    "sys._tables": ("name", "sys._columns", "table_id=(SELECT id FROM sys._tables WHERE name=%s AND system=false)", "number"),  # MonetDB
    "system.tables": ("name", "system.columns", "table=%s AND database=currentDatabase()", "position"),  # ClickHouse (scope to current db)
    "SYS.OBJECTS": ("column_name", "SYS.TABLE_COLUMNS", "table_name=%s", "POSITION"),
    "SYS.SYSTABLES": ("COLUMNNAME", "SYS.SYSCOLUMNS", "REFERENCEID=(SELECT TABLEID FROM SYS.SYSTABLES WHERE TABLENAME=%s)", "COLUMNNUMBER"),
    "SYSIBM.SYSTABLES": ("COLUMNNAME", "SYSIBM.SYSCOLUMNS", "TBNAME=%s", "COLNO"),
    "INFORMATION_SCHEMA.TABLES": ("column_name", "INFORMATION_SCHEMA.COLUMNS", "table_name=%s", "ordinal_position"),
}


# pattern-match floor operators: (op, multi-char wildcard, single-char wildcard); GLOB
# (case-sensitive, literal '_') is preferred over LIKE
_PREFIX = (
    ("GLOB", "*", "?"),         # SQLite: case-SENSITIVE, and '_' is literal (preferred)
    ("LIKE", "%", "_"),         # near-universal core SQL (often case-insensitive)
    ("SIMILAR TO", "%", "_"),   # SQL:2003 (PostgreSQL/H2/HSQLDB/Vertica): last-resort floor when LIKE+GLOB are both filtered; SAME %/_ wildcards as LIKE but its other regex metachars need escaping (see _SIMILAR_META)
)


# characters SIMILAR TO treats as regex metacharacters (beyond the %/_ wildcards): a
# literal one in the extracted value must be backslash-escaped or the pattern mismatches
_SIMILAR_META = frozenset("%_|*+?(){}[].\\^$")


# identifier quoting styles: (open, close); probed against a known-present table
_IDENT_QUOTE = (
    ('"', '"'),         # ANSI: PostgreSQL/Oracle/SQLite/DB2/Firebird/HANA/Snowflake/...
    ('`', '`'),         # MySQL/MariaDB/TiDB
    ('[', ']'),         # SQL Server/Access/Sybase
)


# primary/unique key lookup per catalog: (source, table_col, name_col, constraint_filter);
# the preferred row-ordering key for dump()
# ANSI INFORMATION_SCHEMA key lookup, shared by every catalog whose engine also exposes
# it (MSSQL/Sybase are detected via master..sysdatabases but DO have INFORMATION_SCHEMA)
_ANSI_KEY_SPEC = (
    "INFORMATION_SCHEMA.KEY_COLUMN_USAGE", "table_name", "column_name",
    "constraint_name IN (SELECT constraint_name FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS "
    "WHERE constraint_type IN ('PRIMARY KEY','UNIQUE'))")

_KEY_SPECS = {
    "INFORMATION_SCHEMA.TABLES": _ANSI_KEY_SPEC,
    "master..sysdatabases": _ANSI_KEY_SPEC,     # MSSQL/Sybase: rowid-less, so a PK keyset is the clean ordered walk
    "pg_catalog.pg_tables": (
        "information_schema.key_column_usage", "table_name", "column_name",
        "constraint_name IN (SELECT constraint_name FROM information_schema.table_constraints "
        "WHERE constraint_type IN ('PRIMARY KEY','UNIQUE'))"),
    "SYS.ALL_TABLES": (
        "SYS.ALL_CONS_COLUMNS", "table_name", "column_name",
        "constraint_name IN (SELECT constraint_name FROM SYS.ALL_CONSTRAINTS "
        "WHERE constraint_type IN ('P','U'))"),
}


# physical row-id pseudo-columns: (name, expr, unit); fallback row-ordering for dump()
_ROWID = (
    ("rowid", "ROWID", "int"),          # SQLite (integer); Oracle (opaque string) - unit re-measured
    ("_ROWID_", "_ROWID_", "int"),      # SQLite alias
    ("rowid_oracle", "ROWID", "text"),  # Oracle pseudo-column (opaque, orderable)
    ("ctid", "ctid", "text"),           # PostgreSQL tuple id (page,tuple): MIN-aggregatable + orderable, so a PK-less table's exact-duplicate rows survive the dump instead of collapsing
    ("rrn", "RRN(%s)", "int"),          # IBM Db2 relative record number
)


# row-ids whose comparison bound must be a QUOTED literal, not a CHR()||... build: their
# type (e.g. PostgreSQL 'tid') coerces from an unknown-typed literal ('(0,1)') but NOT
# from a text-typed concatenation, so ctid=CHR(40)||... errors while ctid='(0,1)' works
_ROWID_LITBOUND = frozenset(("ctid",))


# printable ASCII (0x20-0x7E): the equality/ordinal char-scan alphabet
_PRINTABLE = "".join(chr(_) for _ in range(32, 127))


# _PRINTABLE sorted by code point (for ordinal/collation bisection)
_PRINTABLE_SORTED = sorted(_PRINTABLE)


# English-frequency-ordered charset (common letters first) so the equality scan needs
# fewer probes on real text; completed with any remaining printable chars below
_FREQ_ORDER = ("etaoinshrdlcumwfgypbvkjxqz"
               "0123456789_ .-,ETAOINSHRDLCUMWFGYPBVKJXQZ")
_FREQ_ORDER += "".join(c for c in _PRINTABLE if c not in _FREQ_ORDER)


# highest Unicode code point: the upper bound for code-mode bisection
_UNICODE_MAX = 0x10FFFF


# U+FFFD REPLACEMENT CHARACTER: the explicit "could not recover this char" marker
# (extraction emits it instead of ever silently substituting/dropping a character)
_REPL = u"\uFFFD"


# a warning is INFORMATIONAL (the recovered bytes are whole + usable, only case/accent is
# uncertain, or the value was cleanly recovered by an alternate route) if it mentions one of
# these; anything else is an INTEGRITY warning meaning the bytes may be wrong/partial, which
# clears `complete`. Lets `complete` be a clean invariant: True == trustworthy whole value.
_SOFT_WARNINGS = ("case", "collation", "recovered via hex")


def _hardWarnings(warns):
    """The integrity-class warnings in `warns` (those that impugn the recovered bytes)."""
    return [w for w in warns if not any(s in w for s in _SOFT_WARNINGS)]


# py2/py3 shim: integer code point -> single char
try:
    _unichr = unichr                    # py2
except NameError:
    _unichr = chr                       # py3

# py2/py3 shim: the py2 unicode text type (str on py3)
try:
    _unicode = unicode                  # py2
except NameError:
    _unicode = str                      # py3


def _native(s):
    # embed a literal as the native str type: on py2 a unicode value is encoded to
    # utf-8 bytes so the byte-string SQL templates ('{expr}'.format(...)) don't force
    # an ascii encode of non-ASCII data; on py3 str is already unicode-clean.
    if str is bytes and isinstance(s, _unicode):    # py2 only
        return s.encode("utf-8")
    return s


__all__ = [_n for _n in list(globals()) if not _n.startswith('__') and _n != 'binascii']
