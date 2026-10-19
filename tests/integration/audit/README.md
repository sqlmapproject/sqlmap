# Disposable security audit matrix

Run from the repository root on a local Docker host:

```sh
python3 tests/integration/audit/run.py
```

Requires Python 3, Docker Compose, Internet access for images and roughly 12 GB
available memory. The SQL Server image requires an x86-64 host. Oracle image
support also depends on host architecture and page size. Application drivers are
installed only inside the fixture image; sqlmap gains no dependencies.

The runner creates an isolated `sqlmap-audit-<pid>` Compose project. Database ports
are internal; deliberately injectable HTTP endpoints bind to random localhost
ports. Credentials are synthetic and fixed for these disposable databases. The
runner does not access the remote sqlmap testbed or existing database services.
It removes its own containers, networks and volumes on completion, including a
failed assertion. `--keep` retains them for investigation; remove the retained
project with `docker compose -p <project> -f tests/integration/audit/compose.yml down --volumes`.

The matrix covers MySQL 8, MariaDB 10.11, PostgreSQL 16, SQL Server 2022 and
Oracle Free 23, with administrator, application and restricted accounts. Two
additional MySQL instances exercise unrestricted and disabled file operations.
It compares native metadata results with real UNION SQLi for every account and
boolean blind SQLi for each engine's application account, using five threads.
Variable listings retain total counts and show at most 20 details. Additional
scenarios cover oversized listings, escaped control characters, confirmed empty
queries, RLS enforcement and command advice with and without stacked execution.
It also checks that audits leave configuration unchanged, that revoking grants
and changing settings changes the result, and that database root with FILE
privilege still cannot read a root-only fixture file. Filesystem probes and
configuration changes belong to the fixture provisioner; `--audit` performs
metadata reads only.

Use `--native-only` for database queries and permission/configuration/filesystem
checks without the HTTP scans. Logs and native reference results go to a printed
temporary directory. For a previously seeded retained project:

```sh
python3 tests/integration/audit/run.py --project sqlmap-audit-<id> --reuse --keep
```
