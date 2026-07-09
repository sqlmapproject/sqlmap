# sqlmap architecture

A contributor-oriented map of how sqlmap is put together: the major components,
how a run flows through them, and where to start looking for a given concern.

> This is a map, not a spec. It describes the durable structure and data flow; for
> exact signatures, option names, and enumerable lists (tampers, DBMSes, options),
> the source is authoritative. **When this document disagrees with the code, the code wins.**

sqlmap runs on both Python 2.7 and 3.x; sources are kept pure-ASCII unless a literal
non-ASCII byte is unavoidable. Compatibility shims live in `lib/core/compat.py` and
`thirdparty/six`.

---

## 1. Entry points

| Entry | File | Purpose |
|-------|------|---------|
| CLI | `sqlmap.py` -> `main()` | the scanner. Applies runtime patches, parses options, runs a scan. |
| REST API | `sqlmapapi.py` | `-s` server / `-c` client wrappers around `lib/utils/api.py`. |

`main()` (sqlmap.py) does, in order: `dirtyPatches()` (monkey-patches stdlib for
quirks/security - see below), `setPaths()`, `init()` (option parsing + environment
setup), then dispatches to `start()` for a normal scan, or to the self-tests
(`--smoke` / `--vuln-test` / `--api-test`) in `lib/core/testing.py`.

---

## 2. Global state: `conf` and `kb`

Almost everything hangs off two process-global singletons defined in `lib/core/data.py`,
both `AttribDict` (attribute-accessible dicts; missing keys read back as `None`):

- **`conf`** - the resolved user configuration (options + derived settings). What the
  user asked for.
- **`kb`** ("knowledge base") - mutable runtime state discovered during a run
  (identified DBMS, injection points, page templates, caches, locks, counters).

The configuration pipeline (`lib/core/`):

- `parse/cmdline.py` - argparse definition of every CLI option.
- `core/optiondict.py` - option name -> type map (used for config-file/API coercion).
- `core/defaults.py` - default values.
- `core/option.py` - the heavy lifter: `_setConfAttributes()`, `_setKnowledgeBaseAttributes()`,
  `_setHTTPHandlers()` (installs the global urllib opener incl. keep-alive), DBMS/encoding
  setup, etc. Merges CLI + config file + defaults into `conf`/`kb`.
- `core/settings.py` - constants, version, regexes, thresholds. **New constants go here.**

Identifiers in the codebase are camelCase.

---

## 3. Top-level layout

| Path | Responsibility |
|------|----------------|
| `lib/core/` | conf/kb model, common helpers, settings, enums, dump, session, agent, option parsing |
| `lib/controller/` | the scan orchestrator (`controller.py`), detection checks (`checks.py`), enumeration dispatch (`action.py`), DBMS handler selection (`handler.py`) |
| `lib/request/` | HTTP layer: `connect.py` (sending), `comparison.py` (the true/false oracle), `inject.py` (value extraction), protocol handlers, response processing |
| `lib/techniques/` | the exploitation engines: `blind/inference.py`, `error/use.py`, `union/{test,use}.py`, `dns/` |
| `lib/parse/` | parsing of inputs: CLI, config, HTTP request/log files, HTML, sitemap, and the XML payload/boundary loader (`payloads.py`) |
| `lib/utils/` | feature modules: `api.py` (REST), `hashdb.py` (session), `crawler.py`, `hash.py` (cracking), `har.py`, `brute.py`, `search.py`, ... |
| `lib/takeover/` | OS-level takeover: shells, file access, UDF, registry, Metasploit, `xp_cmdshell` |
| `plugins/generic/` | DBMS-agnostic enumeration/fingerprint/filesystem/takeover base classes |
| `plugins/dbms/<dbms>/` | per-DBMS subclasses + dialect (one dir per supported DBMS) |
| `tamper/` | payload-mutation scripts (WAF bypass), one `tamper()` per file |
| `data/xml/` | the data-driven engine: `boundaries.xml`, `payloads/*.xml`, `queries.xml`, `errors.xml` |
| `data/` (other) | wordlists/common tables/columns (`txt/`), UDFs (`udf/`), stored procs (`procs/`), shells (`shell/`) |
| `tests/` | stdlib-unittest suite (offline); see section 11 |
| `thirdparty/` | vendored dependencies (six, bottle, chardet, ...) - no pip at runtime |
| `extra/` | auxiliary tools (e.g. `vulnserver` used by `--vuln-test`) |

---

## 4. The scan lifecycle (`lib/controller/controller.py: start()`)

For each target:

1. **Target setup** - `initTargetEnv()` / `setupTargetEnv()` (`lib/core/target.py`):
   resolve URL/params, open the per-target output dir and session file
   (`conf.hashDBFile`), and **resume** anything already known (DBMS, injection points,
   cached values) from the session.
2. **Connection & profiling** (`lib/controller/checks.py`): `checkConnection()`,
   `checkWaf()` (fills `kb.identifiedWafs`), `checkStability()` /
   dynamic-content detection (establishes `kb.pageTemplate`, `kb.matchRatio`).
3. **Heuristics** - `heuristicCheckSqlInjection()` (cheap error-based hint).
4. **Detection** - `checkSqlInjection(place, parameter, value)` per parameter, driven by
   the data engine (section 5). Confirmed points are appended to `kb.injections`.
5. **Fingerprint & handler** - `lib/controller/handler.py: setHandler()` identifies the
   back-end DBMS and assigns `conf.dbmsHandler`, the object through which all
   enumeration is dispatched (section 7).
6. **Action** - `action()` (`lib/controller/action.py`) routes the requested operation
   (`--banner`, `--dbs`, `--tables`, `--dump`, `--sql-query`, `--os-shell`, ...) to
   `conf.dbmsHandler` methods, and feeds results to `conf.dumper`.

If nothing is injectable, the dead-end advisory (level/risk, technique, `--text-only`,
`--tamper` - definitive when `kb.identifiedWafs` is set) is raised as
`SqlmapNotVulnerableException`.

---

## 5. The data-driven detection engine

Detection behavior lives in **data, not code** - `data/xml/`, loaded by
`lib/parse/payloads.py` (`loadBoundaries()`, `loadPayloads()`):

- **`boundaries.xml`** - injection *boundaries*: prefix/suffix pairs and the
  clause/where/parameter-type context they apply to (e.g. quote vs. numeric contexts).
- **`payloads/*.xml`** - the *tests*, one file per technique
  (`boolean_blind`, `error_based`, `inline_query`, `stacked_queries`, `time_blind`,
  `union_query`), each with the request template and the comparison/grep logic that
  decides success.

`getSortedInjectionTests()` (`lib/core/common.py`) orders the candidate tests by the
identified/likely DBMS, `--level`, and `--risk`. The **agent** (`lib/core/agent.py`)
forges the actual payload string - applying boundary prefix/suffix, the `[RANDNUM]`/
`[DELIMITER]`-style markers, comments, and tamper scripts. Requests go out via
`lib/request/connect.py`; the **oracle** `lib/request/comparison.py` decides true/false
by comparing the response against `kb.pageTemplate` (difflib ratio vs. `kb.matchRatio`,
plus titles/errors/HTTP-code signals).

---

## 6. Exploitation techniques

Once a parameter is injectable, value extraction is dispatched by
`lib/request/inject.py: getValue()` to the matching engine in `lib/techniques/`:

| Technique | Engine | Mechanism |
|-----------|--------|-----------|
| boolean-based blind | `blind/inference.py: bisection()` | binary-search each character via true/false oracle |
| time-based blind / stacked | `blind/inference.py` (time compare) | same bisection, oracle is a measured delay |
| error-based | `error/use.py: errorUse()` | parse the value straight out of a provoked DB error |
| UNION query | `union/{test,use}.py` | column-count detection then `UNION SELECT` extraction |
| inline query | (inline, via inject) | value embedded in the original query position |
| DNS exfiltration | `dns/` | `--dns-domain` out-of-band channel |

`bisection()` is the hot loop; it caches the `--charset` table in
`kb.cache.charsetAsciiTbl` and respects the `kb.disableShiftTable` runaway-guard latch
(intentional). Multi-threaded extraction is coordinated via `kb.locks` and
`getCurrentThreadData()` (`lib/core/threads.py`).

---

## 7. DBMS abstraction

Enumeration is DBMS-agnostic at the top and specialized underneath:

- **`plugins/generic/`** - base classes for each concern: `fingerprint.py`,
  `enumeration.py`, `databases.py`, `entries.py`, `users.py`, `filesystem.py`,
  `takeover.py`, `syntax.py`, `misc.py`, `search.py`, `custom.py`, `connector.py`
  (direct DB connection for `-d`).
- **`plugins/dbms/<dbms>/`** - one directory per supported DBMS, subclassing the generic
  pieces and supplying dialect specifics.
- **`data/xml/queries.xml`** - per-DBMS SQL query templates (banner, current user, table
  enumeration, casting, etc.) keyed by DBMS. The generic code asks for a query by name;
  the dialect comes from XML.

`conf.dbmsHandler` (set in `handler.py`) is the live object that `action()` calls into.

---

## 8. Output and session

- **Output** - `conf.dumper` is a `Dump` instance (`lib/core/dump.py`): console tables
  plus per-table file export in CSV / HTML / SQLITE / JSONL (`--dump-format`). Logging
  is via `logger` (`lib/core/log.py`).
- **Session / resume** - each target gets a SQLite session file
  (`<output>/<host>/session.sqlite`). `hashDBWrite()` / `hashDBRetrieve()`
  (`lib/core/common.py`, backed by `lib/utils/hashdb.py`) cache injection points,
  fingerprint, and extracted values so a re-run *resumes* instead of re-testing
  (`--flush-session` discards it; `--fresh-queries` ignores cached query results). A
  stale-session nudge fires on resume when the file is older than `HASHDB_STALE_DAYS`.

---

## 9. Request layer and tampering

`lib/request/connect.py` (`Connect.getPage`) is the single HTTP chokepoint. Around it:
protocol handlers (`httpshandler`, `redirecthandler`, `chunkedhandler`, `rangehandler`,
persistent connections via `lib/request/keepalive.py`), response processing (`basic.py`), and the
comparison oracle (`comparison.py`).

**Tamper scripts** (`tamper/`) mutate the payload just before sending to evade WAF/IPS.
Each file exposes a `tamper(payload, **kwargs)` and a `__priority__`; `--tamper=a,b,c`
chains them in priority order. They are payload-string transforms only (no engine
coupling), which is why they compose freely.

---

## 10. REST API and JSON report

`lib/utils/api.py` runs a Bottle server (`sqlmapapi.py -s`) that drives sqlmap scans as
subprocesses and exposes them over HTTP. Key pieces: `DataStore`/`Task` (task registry),
an IPC SQLite `Database` (the subprocess writes results/logs/errors back through
`StdDbOut`), and the route handlers (`/task/*`, `/option/*`, `/scan/*`, `/version`, ...).
The contract is documented in `sqlmapapi.yaml` (OpenAPI) and `REST-API.md`.

`--report-json` reuses the *same* assembly code (`_assembleData` / `_sanitizeScanData`)
that the `/scan/<id>/data` endpoint uses, so the CLI report and the API result can't
drift; `RESTAPI_VERSION` is the API contract version (major exposed as integer).

---

## 11. Tests and self-tests

Two complementary layers:

- **Offline unit/regression suite** (`tests/`) - stdlib `unittest` only (no pytest/pip),
  green on py2 + py3. `_testutils.py` bootstraps global state and provides the
  property/fuzz harness (`Rng` - a cross-version-identical PRNG - and `for_all`). Run:
  `python -B -m unittest discover -s tests -p "test_*.py"` (`-B` matters: a cached `.pyc`
  makes a `getFileType(__file__)` doctest see `binary`).
- **In-tree self-tests** (`lib/core/testing.py`, hidden switches): `--smoke-test`
  (doctests + regex sanity over the whole tree), `--vuln-test` (end-to-end scans against
  the bundled `extra/vulnserver`), `--api-test` (live REST round-trip). The CI workflow
  (`.github/workflows/tests.yml`) runs all of these.

---

## 12. "Where do I start for ...?"

| I want to change... | Start in |
|---------------------|----------|
| a CLI option | `lib/parse/cmdline.py` (+ `optiondict.py`, `defaults.py`) |
| a constant/threshold | `lib/core/settings.py` |
| how injection is *detected* | `data/xml/boundaries.xml` + `data/xml/payloads/*.xml`, then `lib/controller/checks.py` |
| how a value is *extracted* | `lib/request/inject.py` + the relevant `lib/techniques/` engine |
| the true/false decision | `lib/request/comparison.py` |
| a per-DBMS query/dialect | `data/xml/queries.xml` + `plugins/dbms/<dbms>/` |
| enumeration behavior | `plugins/generic/*.py` |
| dump/output format | `lib/core/dump.py` |
| a WAF-bypass transform | add a file under `tamper/` |
| the REST API surface | `lib/utils/api.py` (+ keep `sqlmapapi.yaml` in sync) |
| session/resume behavior | `lib/utils/hashdb.py` + `hashDB*` in `lib/core/common.py` |
| a stdlib monkey-patch / security shim | `lib/core/patch.py` |
