#!/usr/bin/env bash
#
# Disposable boundary-check lab. Spins up throwaway MySQL + PostgreSQL containers, runs the
# validator against them, and tears everything down again (even on Ctrl-C / failure).
#
# It uses uncommon host ports and points the tool at them via BC_* env vars, so it will NOT collide
# with any DBMS you already have running (including sqlmap's usual bench). These two engines start in
# seconds and exercise the boolean, time and inband oracles plus the MySQL-only (backtick, double-
# quote, fulltext) and PostgreSQL-only (dollar-quote) families. MSSQL and Oracle are slower/heavier -
# see README.md to add them for full coverage; the tool reports absent engines as "skipped".
#
# Usage:   ./run.sh            (requires docker + python drivers pymysql, psycopg2 - see README.md)
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MYSQL_PORT=13399
PG_PORT=15499

cleanup() { docker rm -f bcheck-mysql bcheck-pg >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup   # clear any stale containers from a previous aborted run

echo "[*] starting throwaway MySQL (:$MYSQL_PORT) and PostgreSQL (:$PG_PORT) ..."
docker run -d --rm --name bcheck-mysql -e MYSQL_ROOT_PASSWORD=root -p ${MYSQL_PORT}:3306 mysql:8.4 >/dev/null
docker run -d --rm --name bcheck-pg   -e POSTGRES_USER=esp -e POSTGRES_PASSWORD=pass -e POSTGRES_DB=espdb -p ${PG_PORT}:5432 postgres:16 >/dev/null

echo "[*] waiting for readiness ..."
# a real query, not just ping: the mysql:8.4 image accepts pings mid-init then restarts once
for _ in $(seq 1 90); do docker exec bcheck-mysql mysql -uroot -proot -e "SELECT 1" >/dev/null 2>&1 && break; sleep 2; done
for _ in $(seq 1 60); do docker exec bcheck-pg   pg_isready -U esp                   >/dev/null 2>&1 && break; sleep 1; done

echo "[*] running boundarycheck ..."
# only touch the throwaway containers we just created; force MSSQL/Oracle to skip (closed ports) so
# this never connects to - and creates/drops tables on - whatever might be listening on their defaults.
BC_MYSQL="127.0.0.1:${MYSQL_PORT}:root:root" \
BC_POSTGRES="127.0.0.1:${PG_PORT}:esp:pass:espdb" \
BC_MSSQL="127.0.0.1:59998:x:x" \
BC_ORACLE="127.0.0.1:59997:x:x:x" \
python3 "$HERE/boundarycheck.py"

echo "[*] done. MSSQL/Oracle were not started here, so their engine-specific boundaries show in the"
echo "    review list - add them per README.md for full coverage. Tearing down (trap removes containers)."
