# dbwire

Minimal, dependency-free database wire-protocol clients used as a fallback for sqlmap's direct
(`-d`) connection mode.

## What this is

sqlmap's `-d` mode talks to a database server directly instead of through an injection point. It
normally does so via a native driver (`psycopg2`, `pymysql`, `pymssql`, ...) or, if one is missing,
via SQLAlchemy. When neither is installed, `dbwire` provides a small pure-python client so that `-d`
still works out of the box.

Every module here is written against the database's **wire protocol** using only the Python standard
library (`socket`, `struct`, `hashlib`, `hmac`, `base64`, `urllib`). There are no third-party
dependencies, and the sources run unmodified on Python 2.7 and Python 3.

## Coverage

A wire protocol is shared across a whole family of products, so one client serves several engines:

| Module          | Protocol            | Engines |
|-----------------|---------------------|---------|
| `postgres.py`   | PostgreSQL v3       | PostgreSQL, CockroachDB, CrateDB, Redshift, Greenplum |
| `mysql.py`      | MySQL client/server | MySQL, MariaDB, TiDB, Aurora (MySQL), Percona |
| `tds.py`        | TDS                 | Microsoft SQL Server, Sybase |
| `firebird.py`   | Firebird wire       | Firebird 3 / 4 / 5 |
| `clickhouse.py` | HTTP (TabSeparated) | ClickHouse and HTTP-compatible forks |
| `monetdb.py`    | MAPI                | MonetDB |
| `presto.py`     | HTTP/REST (JSON)    | Presto, Trino |

The mapping from a DBMS to its module lives in `lib/core/dicts.py` (`DBWIRE_MODULES`). The connector
tier order is: native driver, then SQLAlchemy, then dbwire.

## Interface

Each module exposes a small [PEP 249](https://peps.python.org/pep-0249/) (DB-API 2.0) subset:

- `connect(host, port, user, password, database, connect_timeout, ...)` -> `Connection`
- `Connection.cursor()`, `.commit()`, `.rollback()`, `.close()`
- `Cursor.execute(query)`, `.fetchall()`, `.fetchone()`, `.close()`, `.description`, `.rowcount`
- the shared exception hierarchy in `__init__.py` (`Error` -> `InterfaceError` / `DatabaseError` ->
  `OperationalError` / `DataError` / `IntegrityError` / `ProgrammingError` / `InternalError` /
  `NotSupportedError`)

It is deliberately read-oriented for sqlmap's use: `execute()` takes a fully-formed query string
(no parameter binding), statements auto-commit, and binary column values are returned as `bytes` so
that sqlmap renders them as hex.

## Scope and limitations

This is a fallback for `-d`, not a general-purpose driver. It intentionally does not implement
parameter binding, prepared statements, bulk load/`COPY`, or TLS. Notable per-protocol notes:

- **PostgreSQL** - `trust`, cleartext, MD5 and SCRAM-SHA-256 authentication.
- **MySQL** - `mysql_native_password` and the `caching_sha2_password` fast path. Full
  `caching_sha2_password` authentication over a plaintext connection requires RSA/TLS and is not
  supported; use a `mysql_native_password` account for the dependency-free path.
- **TDS** - cleartext login only. Servers that force encryption (for example Azure SQL Database)
  require TLS and are not supported here; the native driver or SQLAlchemy tier covers those.
- **Firebird** - SRP-256 (and SRP) authentication with ChaCha20 or RC4 wire encryption, as required by
  default on Firebird 3 and later. Legacy (pre-SRP) authentication is not implemented.

When a case is not supported, the client raises a clear `NotSupportedError` rather than returning
wrong data, so `-d` cleanly falls through to another connector tier where possible.

---

Part of [sqlmap](https://sqlmap.org). See the top-level `LICENSE` for copying permission.
