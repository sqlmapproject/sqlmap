# Esperanto

A DBMS-agnostic blind-extraction engine that speaks one "esperanto" at any SQL back-end, driven by
nothing but a boolean oracle.

## What this is

Ordinary blind SQL injection retrieval needs to know the back-end first: sqlmap fingerprints the
DBMS, loads that dialect's `queries.xml` row, and extracts with it. When the DBMS cannot be
identified - an unknown or heavily-firewalled target, an exotic engine, a fork that answers unlike
its parent - that pipeline dead-ends.

Esperanto removes the prerequisite. Given only a **boolean oracle** - a callable
`oracle(condition) -> bool` that reports whether an arbitrary SQL boolean expression holds at the
target - it discovers the dialect from scratch (string concatenation, substring / length /
character-code functions, the usable comparison operator, the catalog surface) and then extracts
data character-by-character, without ever being told which DBMS is on the other end.

The candidate SQL forms it probes are distilled from sqlmap's own `data/xml/queries.xml` across all
supported DBMSes: rather than fingerprint-then-load-one-dialect, it reuses that accumulated knowledge
as a single language it tries to speak at any backend. The engine is self-contained (no sqlmap
imports) and runs unmodified on Python 2.7 and Python 3.

## Usage

Inside sqlmap, via the `--esperanto` switch. sqlmap detects the boolean-blind injection as usual,
then hands the engine its own oracle (`checkBooleanExpression`, which rides the full request /
comparison / WAF stack) instead of fingerprinting. The normal enumeration switches then work against
an unidentified back-end:

```
python sqlmap.py -u 'http://host/vuln?id=1' --esperanto --banner --tables --dump -T users
```

Standalone, straight from this directory (no sqlmap, no `PYTHONPATH`):

```
python run.py -u 'http://host/vuln?id=1*' --tables --dump -T users
python run.py -u 'http://host/vuln?id=1*' --string <true-marker> --dump -T users -C uname,pass
python run.py --self-test
```

The `*` (or an explicit `[INFERENCE]`) marks the injection point; without one it defaults to the end
of the URL. The true/false oracle is taken from `--string` / `--code`, or
auto-calibrated from the response when none is given.

## How it works

Discovery is a set of capability ladders. For each primitive it tries the known SQL forms in turn and
keeps the first that a small set of probes proves correct, so a backend that lacks - or a WAF that
filters - one form falls through to the next rather than failing:

| Primitive        | Ladder (first that works wins) |
|------------------|--------------------------------|
| Concatenation    | `\|\|`, `CONCAT()`, `+`, `&` |
| Substring        | `SUBSTR` / `SUBSTRING` / `MID`, else `LEFT`/`RIGHT` composition |
| Length           | a length function, else derived from the substring's end |
| Character read   | code point (`ASCII`/`UNICODE`/`ORD`/...), collation-forced byte order, hex, ordinal, `=` scan |
| Comparison       | `>`, else `BETWEEN`, else an operator-free ordered form (`SIGN`/`ABS`/`LEAST`/...), else order-free `IN()` |
| No-substring floor | `LIKE` / `GLOB` / `SIMILAR TO` pattern matching |

Each candidate is accepted only against a semantic check (for example, the comparison ladder is
validated across a signed truth table, not two positive samples), so a rewriting layer that turns
`>` into `>=` is rejected rather than silently mis-reading every count and length.

Discovery produces a `Dialect`; `identify()` then fuses catalog family, required dual-table and
version-banner evidence into a best-guess product. Enumeration walks catalogs by keyset
(`MIN(name) WHERE name > prev`) with no dialect row-limiter, and `dump()` reconstructs rows by a
discovered primary/unique key, else a physical row-id, else the row's own value.

## Interface

```python
from extra.esperanto import Esperanto

esp = Esperanto(oracle)          # oracle(condition_str) -> bool
esp.discover()                   # ladder out the dialect
esp.identify()                   # best-guess product + evidence
esp.extract("(SELECT ...)")      # one scalar, char-by-char
esp.dump("users", schema="app")  # {columns, rows, complete, exact, keyed_by}
esp.enumerate("table")           # keyset catalog walk
```

- The **oracle contract** is strict tri-state: return `True` / `False` for an observed result; a
  transport or observation failure must raise (or return a non-boolean), which the engine treats as
  *undecided* rather than a definitive `False`. A wrong-dialect or unsupported probe is expected to be
  reported as `False` by the oracle itself.
- `buildHandler()` is the sqlmap adapter (`--esperanto`), a `dbmsHandler` that maps sqlmap's
  enumeration calls onto the engine. sqlmap-core imports are deferred inside it so the rest of the
  package stays dependency-free.
- `strategy()` freezes the discovered dialect into an immutable `InferenceStrategy` of pure `render_*`
  methods (no oracle, no loop), and `hostExtract()` is a reference host loop that extracts using only
  a strategy plus an oracle.

## Integrity model

Every recovered value carries an `Integrity` classification so a caller can tell "we visited every
position" apart from "the bytes are provably the source's":

| State                 | Meaning |
|-----------------------|---------|
| `EXACT`               | proven byte-identical to the source (or a proven `NULL`) |
| `WHOLE_BUT_AMBIGUOUS` | every position read, but case/accent is uncertain (collation-dependent comparison, no byte-exact primitive) |
| `TRUNCATED`           | a bounded prefix; the source continues |
| `UNRESOLVED`          | a character could not be recovered |
| `FAILED`              | could not observe or verify |

The engine is designed to fail closed: it never manufactures a `False` from an unobservable probe,
never silently substitutes or drops a character, distinguishes `NULL` from empty string, and reports
a dump along two independent axes - `complete` (coverage: every row) and `exact` (content: the values
are byte-faithful). `EXACT` is claimed only when a byte-faithful witness backs the value.

## Scope and limitations

This is a last-resort engine for targets a normal fingerprint cannot reach, not a replacement for
sqlmap's native retrieval. Known boundaries:

- **Throughput.** Extraction is one boolean question per request, char-by-char; it is bounded by the
  information theory of a boolean oracle (about one bit per request) and by network latency. It is
  built for reach, not speed.
- **Namespace.** Database, schema and owner are currently handled as a single scope name. Fully
  separated, backend-aware qualification (for example SQL Server `database.schema.table` via a
  `sys.schemas` join) is not yet modelled, so schema scoping on those engines is best-effort.
- **Encoding.** The back-end's declared character set is read from its own catalog and mapped to a
  codec (with the vendor quirks - MySQL `latin1` is Windows-1252, Oracle `WE8MSWIN1252` too),
  resolving the common cases definitively. A column whose character set differs from the database
  default, or a set outside the mapped list, decodes best-effort and is marked non-exact rather
  than asserted.
- **Strategy hand-off.** The exported `InferenceStrategy` / `hostExtract()` drive the character
  comparison modes under an ordered comparator; they do not yet drive the pattern-only or
  membership-only modes, and the frozen field set does not yet carry every discovered semantic.

Where a value cannot be recovered exactly, the engine surfaces its `Integrity` rather than presenting
it as trustworthy.

## Self-test

```
python run.py --self-test
```

runs the engine against an in-memory SQLite oracle across every compare mode plus identification,
byte extraction, noisy-oracle quorum voting, the fail-closed integrity invariants and the frozen
strategy hand-off. The regression corpus lives in `tests/test_esperanto.py`.

---

Part of [sqlmap](https://sqlmap.org). See the top-level `LICENSE` for copying permission.
