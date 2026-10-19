#!/usr/bin/env python3
"""Opt-in Docker audit matrix. Runtime sqlmap itself acquires metadata only.

This fixture provisioner deliberately changes settings, grants and synthetic files inside
its own disposable containers, then verifies the audit over native SQL and real SQLi.
"""
from __future__ import print_function

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
from _testutils import bootstrap, set_dbms
bootstrap()
from lib.core.enums import DBMS, FORK, EXPECTED
from lib.core.common import Backend, getSQLSnippet, unArrayizeValue
from lib.core.data import conf
from lib.core.settings import AUDIT_MAX_ROWS
from lib.request import inject
from plugins.generic.databases import Databases

ENGINES = {'mysql': (DBMS.MYSQL, 'root'), 'mariadb': (DBMS.MYSQL, 'root'),
           'postgres': (DBMS.PGSQL, 'postgres'), 'mssql': (DBMS.MSSQL, 'sa'),
           'oracle': (DBMS.ORACLE, 'audit_owner'),
           'mysql-open': (DBMS.MYSQL, 'root'), 'mysql-disabled': (DBMS.MYSQL, 'root')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', default='sqlmap-audit-%d' % os.getpid())
    parser.add_argument('--reuse', action='store_true', help='Use an already seeded audit project')
    parser.add_argument('--keep', action='store_true', help='Keep this disposable project for debugging')
    parser.add_argument('--native-only', action='store_true', help='Skip the HTTP SQLi matrix')
    args = parser.parse_args()
    if not re.match(r'^sqlmap-audit-[a-z0-9-]+$', args.project):
        parser.error('project must have the sqlmap-audit- prefix')
    compose = ['docker', 'compose', '-p', args.project, '-f', str(LAB / 'compose.yml')]
    logs = Path(tempfile.mkdtemp(prefix='sqlmap-audit-matrix-'))
    print('Logs: %s' % logs, flush=True)

    def command(argv, data=None, check=True, timeout=240):
        result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=timeout)
        if check and result.returncode:
            raise AssertionError('%s\n%s\n%s' % (' '.join(argv), result.stdout, result.stderr))
        return result

    def sql(engine, account, query, check=True):
        result = command(compose + ['exec', '-T', 'web-' + engine, 'python', '/lab/probe.py', account], query, check)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def native(engine, account, statement=False):
        dbms = ENGINES[engine][0]
        set_dbms(dbms)
        # MariaDB is a MySQL plugin fork; native probes don't run the normal fingerprint.
        original_fork = Backend.isFork
        Backend.isFork = staticmethod(lambda fork: engine == 'mariadb' and fork == FORK.MARIADB)
        original_direct = conf.direct
        conf.direct = statement
        original = inject.getValue
        calls = []
        def getValue(query, **kwargs):
            assert query.startswith('SELECT ')
            calls.append(query)
            rows = sql(engine, account, query, check=False)
            return unArrayizeValue(rows) if kwargs.get("expected") == EXPECTED.INT else rows
        inject.getValue = getValue
        try:
            result = Databases().getAudit()
            assert calls
            assert not any(line.startswith('OS boundary:') for line in result)
            return sorted(set(result))
        finally:
            conf.direct = original_direct
            inject.getValue = original
            Backend.isFork = staticmethod(original_fork)

    def scan(engine, account, technique, expected):
        address = command(compose + ['port', 'web-' + engine, '8080']).stdout.strip()
        url = 'http://%s/%s/get_int?id=1' % (address, account)
        label = '%s-%s-%s' % (engine, account, technique)
        cmd = [sys.executable, str(ROOT / 'sqlmap.py'), '-u', url,
               '--dbms=' + ENGINES[engine][0], '--batch', '--technique=' + technique,
               '--threads=5', '--audit', '--skip-waf', '--disable-precon', '--flush-session',
               '--output-dir=' + str(logs / label)]
        result = command(cmd, check=False, timeout=900)
        (logs / (label + '.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, label
        audit_output = re.search(r'^database security audit[^\n]*\n((?:\[\*\] [^\n]*\n)+)', result.stdout, re.M)
        assert audit_output, label
        actual = sorted(set(re.findall(r'^\[\*\] (.*)$', audit_output.group(1), re.M)))
        assert actual == expected, '%s: missing=%r extra=%r' % (label, sorted(set(expected)-set(actual)), sorted(set(actual)-set(expected)))
        print('SQLi %s PASS' % label, flush=True)

    try:
        if not args.reuse:
            command(compose + ['build', 'web-mysql'])
            command(compose + ['up', '-d'])
            with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
                futures = [pool.submit(command, compose + ['exec', '-T', 'web-' + engine, 'python', '/lab/seed.py']) for engine in ENGINES]
                for future in futures:
                    future.result()
        expected = {}
        for engine, (dbms, admin) in ENGINES.items():
            for alias, account in (('admin', admin), ('app', 'audit_app'), ('limited', 'audit_limited')):
                snapshot_query = getSQLSnippet(dbms, 'audit_configuration_mariadb' if engine == 'mariadb' else 'audit_configuration', LIMIT=str(AUDIT_MAX_ROWS))
                before = sql(engine, admin, snapshot_query) if alias == 'admin' else None
                result = native(engine, account)
                if alias == 'admin':
                    assert sql(engine, admin, snapshot_query) == before, 'audit changed configuration'
                expected[engine, alias] = result
                (logs / ('%s-%s-native.json' % (engine, alias))).write_text(json.dumps(result, indent=2))
                assert any('/ effective account:' in line or '/ effective login:' in line for line in result)
                if alias == 'admin':
                    assert not any(re.match(r'^(identity|configuration|privileges|file access): retrieval failed', line) for line in result), (engine,result)
                if engine == 'postgres' and alias == 'app':
                    assert 'privileges / pg_read_server_files: yes' in result
                    assert 'privileges / pg_execute_server_program: no' in result
                if engine == 'mssql' and alias == 'limited':
                    assert 'configuration: SELECT permission missing on master.sys.configurations' in result
                    assert 'linked servers: SELECT permission missing on master.sys.servers' in result
                if engine == 'oracle' and alias == 'app':
                    assert any('AUDIT_FILES [READ]' in line for line in result)
                if engine == 'oracle' and alias == 'limited':
                    assert 'directory grants / visible directory grants: 0' in result
                    assert any(line.startswith('configuration: retrieval failed') for line in result)
                print('Native %s/%s PASS' % (engine,alias), flush=True)

        # Database root with FILE still cannot read files denied to the service OS user.
        for engine in ('mysql', 'mariadb', 'mysql-open', 'mysql-disabled'):
            container = command(compose + ['ps', '-q', engine]).stdout.strip()
            command(['docker','exec','-u','0',container,'sh','-c',
                     'mkdir -p /var/lib/mysql-files; printf AUDIT_READABLE > /var/lib/mysql-files/readable.txt; '
                     'printf AUDIT_PRIVATE > /var/lib/mysql-files/root-only.txt; '
                     'printf AUDIT_OUTSIDE > /tmp/audit-outside.txt; '
                     'chmod 644 /var/lib/mysql-files/readable.txt /tmp/audit-outside.txt; '
                     'chmod 600 /var/lib/mysql-files/root-only.txt'])
            readable = sql(engine, 'root', "SELECT LOAD_FILE('/var/lib/mysql-files/readable.txt')")[0][0]
            private = sql(engine, 'root', "SELECT LOAD_FILE('/var/lib/mysql-files/root-only.txt')")[0][0]
            outside = sql(engine, 'root', "SELECT LOAD_FILE('/tmp/audit-outside.txt')")[0][0]
            assert private is None
            assert command(['docker','exec','-u','mysql',container,'test','-r','/var/lib/mysql-files/root-only.txt'],check=False).returncode != 0
            if engine == 'mysql-disabled':
                assert readable is None and outside is None
                assert any(line in expected[engine,'admin'] for line in ('file access / secure_file_priv: <NULL>', 'file access / secure_file_priv: NULL'))
                assert any('secure_file_priv=NULL blocks' in line for line in expected[engine,'admin'])
            elif engine == 'mysql':
                assert readable is not None and outside is None
            else:
                assert readable is not None and outside is not None
                assert ('file access / secure_file_priv: <NULL>' if engine == 'mariadb' else 'file access / secure_file_priv: <empty>') in expected[engine,'admin']
                assert any('no directory restriction' in line for line in expected[engine,'admin'])
            assert not any('OS boundary:' in line for line in expected[engine,'admin'])
            print('Filesystem boundary %s PASS' % engine, flush=True)

        # Changes are made by this fixture provisioner, never by --audit.
        sql('postgres','postgres','REVOKE pg_read_server_files FROM audit_app')
        changed = native('postgres','audit_app')
        assert 'privileges / pg_read_server_files: no' in changed
        sql('postgres','postgres','GRANT pg_read_server_files TO audit_app')
        sql('mssql','sa',"EXEC sp_configure 'clr enabled',0; RECONFIGURE")
        assert 'configuration / clr enabled: disabled' in native('mssql','audit_app')
        sql('mssql','sa',"EXEC sp_configure 'clr enabled',1; RECONFIGURE")
        sql('oracle','sys','REVOKE SELECT ON sys.v_$parameter FROM audit_app')
        assert any(line.startswith('configuration: retrieval failed') for line in native('oracle','audit_app'))
        sql('oracle','sys','GRANT SELECT ON sys.v_$parameter TO audit_app')
        print('Grant/configuration changes reflected by audit PASS', flush=True)

        # A successful zero-row SELECT must not be reported as a failed query.
        from plugins.generic import audit as auditModule
        original_snippet = auditModule.getSQLSnippet
        auditModule.getSQLSnippet = lambda *args, **kwargs: "SELECT audit_key,audit_value FROM (SELECT 'empty' AS audit_key,'Vempty' AS audit_value) audit_rows WHERE 1=0"
        try:
            assert native('mysql','root') == ['configuration: no entries', 'file access: no entries', 'identity: no entries', 'privileges: no entries']
        finally:
            auditModule.getSQLSnippet = original_snippet
        print('Confirmed empty metadata query PASS', flush=True)

        # Independent semantics: row_security=off must fail, not bypass a policy.
        sql('postgres','postgres', 'CREATE TABLE audit_rls (id INT)')
        sql('postgres','postgres', 'INSERT INTO audit_rls VALUES (1),(2)')
        sql('postgres','postgres', 'GRANT SELECT ON audit_rls TO audit_app')
        sql('postgres','postgres', 'ALTER TABLE audit_rls ENABLE ROW LEVEL SECURITY')
        sql('postgres','postgres', 'CREATE POLICY audit_policy ON audit_rls USING (id=1)')
        assert sql('postgres','audit_app','SELECT * FROM audit_rls',check=False) is None
        assert not any('bypasses row-level security' in line for line in native('postgres','audit_app'))
        sql('postgres','postgres','ALTER ROLE audit_app BYPASSRLS')
        assert sql('postgres','audit_app','SELECT COUNT(*) FROM audit_rls')[0][0] == 2
        assert any('bypasses row-level security' in line for line in native('postgres','audit_app'))
        sql('postgres','postgres','ALTER ROLE audit_app NOBYPASSRLS')
        sql('postgres','postgres','DROP TABLE audit_rls')

        sql('postgres','postgres','GRANT pg_execute_server_program TO audit_app')
        no_route = native('postgres','audit_app')
        assert any('COPY FROM PROGRAM privilege granted; no statement execution route identified' in line for line in no_route)
        assert not any('--os-cmd' in line for line in no_route)
        with_route = native('postgres','audit_app', statement=True)
        assert any('COPY FROM PROGRAM privilege granted; use --os-cmd' in line for line in with_route)
        if not args.native_only:
            scan('postgres','app','U',no_route)
            scan('postgres','app','BS',with_route)
        sql('postgres','postgres','REVOKE pg_execute_server_program FROM audit_app')
        print('Independent RLS and execution-route scenarios PASS', flush=True)

        # The fixture creates real metadata beyond the limit and verifies exact totals.
        for index in range(AUDIT_MAX_ROWS + 5):
            sql('mssql','sa', "EXEC sp_addlinkedserver @server=N'audit_bound_%02d',@srvproduct=N'',@provider=N'MSOLEDBSQL',@datasrc=N'bound.invalid'" % index)
        hostile = "audit_control\n[*] forged\r\x1b[2J"
        sql('mssql','sa', "EXEC sp_addlinkedserver @server=N'%s',@srvproduct=N'',@provider=N'MSOLEDBSQL',@datasrc=N'control.invalid'" % hostile)
        bounded = native('mssql','sa')
        assert 'linked servers / visible linked servers: 27' in bounded
        assert sum(line.startswith('linked servers / link ') for line in bounded) == AUDIT_MAX_ROWS
        assert 'Linked servers: showing 20 of 27; use --links for the full list' in bounded
        # The control-character name sorts outside the first details by server_id; test it separately below.
        if not args.native_only:
            scan('mssql','admin','U',bounded)
        for index in range(AUDIT_MAX_ROWS + 5):
            sql('mssql','sa', "EXEC sp_dropserver @server=N'audit_bound_%02d',@droplogins='droplogins'" % index)
        hostile_result = native('mssql','sa')
        assert any('audit_control\\n[*] forged\\r\\x1b[2J' in line for line in hostile_result)
        assert not any('\n' in line or '\r' in line or '\x1b' in line for line in hostile_result)
        if not args.native_only:
            scan('mssql','admin','U',hostile_result)
        sql('mssql','sa', "EXEC sp_dropserver @server=N'%s',@droplogins='droplogins'" % hostile)

        for index in range(AUDIT_MAX_ROWS + 5):
            path = "/tmp/audit-bound-%02d" % index if index else "/tmp/audit\n[*] forged\x1b[2J"
            sql('oracle','sys', "CREATE DIRECTORY AUDIT_BOUND_%02d AS '%s'" % (index,path))
            sql('oracle','sys', 'GRANT READ ON DIRECTORY AUDIT_BOUND_%02d TO audit_owner' % index)
        bounded = native('oracle','audit_owner')
        assert sum(line.startswith('directory grants / ') and '/ visible directory grants:' not in line for line in bounded) == AUDIT_MAX_ROWS
        assert any(line.startswith('Directory grants: showing 20 of ') for line in bounded)
        assert any('audit\\n[*] forged\\x1b[2J' in line for line in bounded)
        if not args.native_only:
            scan('oracle','admin','U',bounded)
        for index in range(AUDIT_MAX_ROWS + 5):
            sql('oracle','sys','DROP DIRECTORY AUDIT_BOUND_%02d' % index)
        print('Bounded listings and control-character scenarios PASS', flush=True)

        if not args.native_only:
            jobs = []
            for engine in ENGINES:
                for alias in ('admin','app','limited'):
                    jobs.append((engine,alias,'U'))
                if engine not in ('mysql-open','mysql-disabled'):
                    jobs.append((engine,'app','B'))
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                futures = [pool.submit(scan,engine,alias,technique,expected[engine,alias]) for engine,alias,technique in jobs]
                for future in futures:
                    future.result()
        print('Audit matrix PASS; logs: %s' % logs, flush=True)
    finally:
        if not args.keep:
            command(compose + ['down','--volumes','--remove-orphans'])


if __name__ == '__main__':
    main()
