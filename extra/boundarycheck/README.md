# boundarycheck

A live cross-DBMS validator for `data/xml/boundaries.xml`. For every reachable DBMS it builds the
**real** injected value for each boundary (through sqlmap's own `agent.prefixQuery` / `suffixQuery` /
`cleanupPayload`, not a re-implementation) across representative host-query contexts, runs it against
the engine, and classifies each boundary via three oracles:

```
W  boolean    TRUE/FALSE variants are valid AND their row counts differ
T  time       an inline conditional sleep delays on TRUE, not on FALSE   (MySQL / PostgreSQL)
I  inband     an injected marker surfaces in the result set              (table cross-join / UNION)
.  inert      valid SQL but no channel discriminated in the contexts tried
x  invalid    a syntax / semantic error on this engine
```

It prints a `boundary x engine` matrix plus the boundaries usable via **no** oracle on any engine
(the "no working context found" review candidates). Any engine that does not connect is **skipped**
and reported as such — never silently counted as covered.

> Scope: covers boolean + inline-time (MySQL/PG) + inband over a sampled set of contexts. It does
> **not** model an error-based oracle, inline time on MSSQL/Oracle (statement/privilege-gated sleep),
> or every possible host context. So a boundary flagged "usable via no oracle" may still work via one
> of those — confirm before acting.

---

## Quick start (throwaway MySQL + PostgreSQL)

```bash
pip install pymysql psycopg2-binary          # python drivers (see below for MSSQL/Oracle)
./run.sh                                       # spins up 2 containers, runs, tears everything down
```

`run.sh` is fully disposable: it creates two containers, waits for readiness, runs the tool, and
removes them again on exit (including Ctrl-C / failure). Nothing persists.

---

## Full lab (all four engines) — step by step

The tool's built-in default endpoints (override any via env var — see below):

| engine     | host:port         | user / pass          | db / service |
|------------|-------------------|----------------------|--------------|
| MySQL      | `127.0.0.1:13306` | `root` / `root`      | —            |
| PostgreSQL | `127.0.0.1:15432` | `esp` / `pass`       | `espdb`      |
| MSSQL      | `127.0.0.1:11433` | `sa` / `Esp_pass123` | —            |
| Oracle     | `127.0.0.1:1521`  | `system` / `oracle`  | `FREEPDB1`   |

### 1. Python drivers

```bash
pip install pymysql psycopg2-binary pymssql oracledb
```

(Install only the ones you need — a missing driver just skips that engine.)

### 2. Start the containers

```bash
# MySQL (fast)
docker run -d --rm --name bcheck-mysql -e MYSQL_ROOT_PASSWORD=root -p 13306:3306 mysql:8.4

# PostgreSQL (fast)
docker run -d --rm --name bcheck-pg -e POSTGRES_USER=esp -e POSTGRES_PASSWORD=pass -e POSTGRES_DB=espdb -p 15432:5432 postgres:16

# MSSQL (slower; ~30-60s to accept connections)
docker run -d --rm --name bcheck-mssql -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD=Esp_pass123 -p 11433:1433 mcr.microsoft.com/mssql/server:2022-latest

# Oracle Free (slowest; first boot can take a few minutes and the image is large)
docker run -d --rm --name bcheck-oracle -e ORACLE_PASSWORD=oracle -p 1521:1521 gvenzl/oracle-free:slim
```

Give MSSQL/Oracle time to finish initialising before running the tool (watch `docker logs -f <name>`).

### 3. Run

```bash
python3 boundarycheck.py            # from anywhere; it locates the sqlmap root itself
```

### 4. Override an endpoint (optional)

```
BC_MYSQL=host:port:user:pass
BC_POSTGRES=host:port:user:pass:db
BC_MSSQL=host:port:user:pass
BC_ORACLE=host:port:user:pass:service      # service_name goes in the db slot
```

```bash
BC_MYSQL=10.0.0.5:3306:root:secret python3 boundarycheck.py
```

### 5. Tear down

```bash
docker rm -f bcheck-mysql bcheck-pg bcheck-mssql bcheck-oracle
```

---

## Notes

- **Faithfulness:** the tool imports the `plugins.dbms.*` packages so each DBMS's `unescaper` is
  registered. Without that, `SELECT '[RANDSTR]'` renders as a bare identifier instead of the real
  `0x`-hex / `CHR()` literal and concat-style boundaries are mis-reported. A `_faithful_or_die()`
  self-check aborts if the registration ever fails to load.
- **Side-effect-free on the target data:** it creates a scratch table `bc` (and a `boundarycheck`
  database on MySQL), and drops them on completion. DML boundaries write only to a spare `note` column.
- Engines are used purely as SQL oracles over localhost throwaway containers — do not point the
  override env vars at anything you care about.
