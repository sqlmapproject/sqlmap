#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Audit acquisition preserves NULL/empty/unknown states and interpretation boundaries.
Real DBMS/SQLi coverage is opt-in under tests/integration/audit/.
"""

import importlib
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms, reset_dbms
bootstrap()

from lib.core.common import getSQLSnippet
from lib.core.data import conf, kb, paths, queries
from lib.core.enums import DBMS, FORK, EXPECTED, PAYLOAD
from lib.core.settings import DBMS_DIRECTORY_DICT
from lib.request import inject
from plugins.generic.audit import Audit
from plugins.generic.databases import Databases

tearDownModule = reset_dbms


class TestAudit(unittest.TestCase):
    def setUp(self):
        self._saved = dict(conf)
        self._cache = kb.data.get('cachedAudit')
        self._getValue = inject.getValue
        self._forced = kb.get('forcedDbms')
        self._injection = kb.injection.data
        self._gadget = kb.get("gadget")
        kb.injection.data = {}
        kb.gadget = None
        conf.direct = False
        kb.data.cachedAudit = []
        set_dbms(DBMS.MYSQL)

    def tearDown(self):
        kb.injection.data = self._injection
        kb.gadget = self._gadget
        inject.getValue = self._getValue
        kb.data.cachedAudit = self._cache
        kb.forcedDbms = self._forced
        conf.clear()
        conf.update(self._saved)

    def test_preserves_null_empty_and_marker_like_values(self):
        inject.getValue = lambda *a, **k: [['null', 'N'], ['empty', 'V'], ['text', 'VNULL'], ['prefix', 'VVvalue'], ['padded   ', 'Vkeep   '], ['trailing\n', 'Vvalue']]
        audit = Audit()
        audit.dbms = DBMS.MYSQL
        self.assertEqual(audit._auditFetch('audit_identity'), {'null': None, 'empty': '', 'text': 'NULL', 'prefix': 'Vvalue', 'padded': 'keep   ', 'trailing\n': 'value'})

    def test_single_row_and_failed_results(self):
        audit = Audit()
        audit.dbms = DBMS.MYSQL
        for value, expected in ((['name', 'Vvalue'], {'name': 'value'}), (None, None), ([], None), (['truncated'], None), ([['key', 'invalid']], None)):
            inject.getValue = lambda *a, **k: value
            self.assertEqual(audit._auditFetch('audit_identity'), expected)

    def test_major_dbmses_dispatch_without_xml_audit_blocks(self):
        inject.getValue = lambda *a, **k: [['effective account', 'Vtest']]
        for dbms in (DBMS.MYSQL, DBMS.PGSQL, DBMS.MSSQL, DBMS.ORACLE):
            set_dbms(dbms)
            d = Databases()
            self.assertNotIn('audit', queries[dbms])
            result = d.getAudit()
            self.assertTrue(any('test' in item for item in result))
            self.assertFalse(any('OS boundary:' in item for item in result))

    def test_unsupported_dbmses_do_not_query(self):
        inject.getValue = lambda *a, **k: self.fail('unsupported DBMS must not query')
        for dbms in queries:
            if dbms not in (DBMS.MYSQL, DBMS.PGSQL, DBMS.MSSQL, DBMS.ORACLE):
                set_dbms(dbms)
                self.assertEqual(Databases().getAudit(), [])

    def test_failures_are_not_reported_as_disabled(self):
        inject.getValue = lambda *a, **k: None
        for dbms in (DBMS.MYSQL, DBMS.PGSQL, DBMS.MSSQL, DBMS.ORACLE):
            set_dbms(dbms)
            result = Databases().getAudit()
            self.assertTrue(any('retrieval failed' in item for item in result))
            self.assertFalse(any(item.endswith(': disabled') for item in result))

    def test_cache_and_bulk_queries_use_existing_extraction(self):
        calls = []
        def getValue(query, **kwargs):
            self.assertTrue(kwargs.get('fromUser'))
            self.assertTrue(kwargs.get('batch'))
            self.assertNotIn('\n', query)
            self.assertNotIn('\r', query)
            calls.append(query)
            return [['effective account', 'Vtest']]
        inject.getValue = getValue
        d = Databases()
        result = d.getAudit()
        count = len(calls)
        self.assertEqual(count, 4)
        self.assertEqual(d.getAudit(), result)
        self.assertEqual(len(calls), count)

    def test_mysql_directory_null_and_empty_are_different(self):
        from plugins.dbms.mysql.audit import Audit as MySQLAudit
        audit = MySQLAudit()
        cases = ((None, 'blocks'), ('NULL', 'blocks'), ('', 'no directory restriction'), ('/var/lib/mysql-files/', 'must be inside'))
        for value, expected in cases:
            result = audit.explain({'file access': {'secure_file_priv': value}})
            self.assertTrue(any(expected in item for item in result))
        self.assertFalse(any('must be inside' in item for item in audit.explain({})))

    def test_mariadb_selects_fork_specific_configuration(self):
        from lib.core.common import Backend
        from plugins.dbms.mysql.audit import Audit as MySQLAudit
        original = Backend.isFork
        Backend.isFork = staticmethod(lambda fork: fork == FORK.MARIADB)
        try:
            self.assertEqual(MySQLAudit().queries[1][1][0], 'audit_configuration_mariadb')
            self.assertFalse(any('blocks' in item for item in MySQLAudit().explain({'file access': {'secure_file_priv': None}})))
        finally:
            Backend.isFork = staticmethod(original)

    def test_mssql_explicit_permission_denial(self):
        from plugins.dbms.mssqlserver.audit import Audit as MSSQLAudit
        audit = MSSQLAudit()
        groups = {'permissions': {'read configuration metadata': '0'}}
        self.assertEqual(audit.failure('configuration', groups), 'configuration: SELECT permission missing on master.sys.configurations')
        self.assertEqual(audit.failure('linked servers', groups), 'linked servers: retrieval failed')

    def test_guidance_requires_retrieved_capabilities(self):
        from plugins.dbms.mysql.audit import Audit as MySQLAudit
        from plugins.dbms.postgresql.audit import Audit as PostgreSQLAudit
        from plugins.dbms.mssqlserver.audit import Audit as MSSQLAudit
        from plugins.dbms.oracle.audit import Audit as OracleAudit
        for audit in (MySQLAudit(), PostgreSQLAudit(), MSSQLAudit(), OracleAudit()):
            self.assertEqual(audit.explain({}), [])
        self.assertEqual(MySQLAudit().explain({'privileges': {'direct FILE grant': '0'}}), [])
        result = MySQLAudit().explain({'file access': {'secure_file_priv': '/allowed/', 'max_allowed_packet': '1024'}, 'privileges': {'direct FILE grant': '1'}})
        self.assertTrue(any('must be inside' in item for item in result))
        self.assertTrue(any('file size < 1024 bytes' in item for item in result))
        result = MySQLAudit().explain({'file access': {'secure_file_priv': None}, 'privileges': {'direct FILE grant': '1'}})
        self.assertFalse(any('FILE granted; use' in item for item in result))
        result = PostgreSQLAudit().explain({'privileges': {'superuser': '0', 'pg_read_server_files': '1', 'pg_execute_server_program': '0'}})
        self.assertTrue(any('--file-read' in item for item in result))
        self.assertFalse(any('--os-cmd' in item for item in result))
        result = MSSQLAudit().explain({'configuration': {'xp_cmdshell': '1'}, 'permissions': {'execute xp_cmdshell': '0'}})
        self.assertTrue(any('EXECUTE permission missing' in item for item in result))
        self.assertFalse(any('--os-cmd' in item for item in result))
        conf.direct = True
        result = MSSQLAudit().explain({'configuration': {'xp_cmdshell': '0'}, 'identity': {'sysadmin': '1'}})
        self.assertTrue(any('can enable xp_cmdshell' in item for item in result))
        result = MSSQLAudit().explain({'configuration': {'xp_cmdshell': '1'}, 'permissions': {'execute xp_cmdshell': '1'}})
        self.assertTrue(any('--os-cmd' in item for item in result))
        result = PostgreSQLAudit().explain({'privileges': {'pg_execute_server_program': '1'}})
        self.assertTrue(any('--os-cmd' in item for item in result))

    def test_execution_advice_uses_known_routes_without_probing(self):
        from plugins.dbms.postgresql.audit import Audit as PostgreSQLAudit
        from plugins.dbms.mssqlserver.audit import Audit as MSSQLAudit
        inject.getValue = lambda *a, **k: self.fail('guidance must not send probes')
        pg = {'privileges': {'pg_execute_server_program': '1'}}
        ms = {'configuration': {'xp_cmdshell': '1'}, 'permissions': {'execute xp_cmdshell': '1'}}
        for audit, groups in ((PostgreSQLAudit(), pg), (MSSQLAudit(), ms)):
            for route in ('none', 'stacked', 'gadget', 'direct'):
                kb.injection.data = {PAYLOAD.TECHNIQUE.STACKED: {'title': 'stacked queries'}} if route == 'stacked' else {}
                kb.gadget = {'command': 'known gadget'} if route == 'gadget' else None
                conf.direct = route == 'direct'
                result = audit.explain(groups)
                self.assertEqual(any('--os-cmd' in item for item in result), route != 'none')
                self.assertEqual(any('no statement execution route identified' in item for item in result), route == 'none')

    def test_rls_setting_does_not_grant_bypass(self):
        from plugins.dbms.postgresql.audit import Audit as PostgreSQLAudit
        result = PostgreSQLAudit().explain({'configuration': {'row_security': 'off'}, 'privileges': {'superuser': '0', 'bypass RLS': '0'}})
        self.assertFalse(any('bypasses' in item for item in result))
        result = PostgreSQLAudit().explain({'privileges': {'bypass RLS': '1'}})
        self.assertTrue(any('bypasses' in item for item in result))

    def test_empty_result_requires_confirmed_zero_count(self):
        audit = Audit()
        audit.dbms = DBMS.MYSQL
        for count, expected in ((0, {}), ('0', {}), ([[0]], {}), (None, None), ('1', None)):
            calls = []
            def getValue(query, **kwargs):
                calls.append(query)
                return count if kwargs.get('expected') == EXPECTED.INT else None
            inject.getValue = getValue
            self.assertEqual(audit._auditFetch('audit_identity'), expected)
            self.assertEqual(len(calls), 2)
        audit.queries = (('empty scope', ('audit_identity',)),)
        inject.getValue = lambda query, **kwargs: 0 if kwargs.get('expected') == EXPECTED.INT else None
        self.assertEqual(audit.getAudit(), ['empty scope: no entries'])

    def test_control_characters_are_escaped_in_facts_and_guidance(self):
        from plugins.dbms.mysql.audit import Audit as MySQLAudit
        value = "/allowed/\n[*] forged\r\x1b[2J"
        inject.getValue = lambda query, **kwargs: [['secure_file_priv', 'V' + value]] if '@@GLOBAL.secure_file_priv' in query else [['name\nforged', 'Vsafe']]
        result = MySQLAudit().getAudit()
        self.assertTrue(any('\\n[*] forged' in item for item in result))
        self.assertFalse(any(any(char in item for char in ('\n', '\r', '\x1b')) for item in result))

    def test_listing_summary_reports_displayed_and_total(self):
        from plugins.dbms.mssqlserver.audit import Audit as MSSQLAudit
        from plugins.dbms.oracle.audit import Audit as OracleAudit
        links = {'visible linked servers': '200', 'link one': 'destination'}
        self.assertIn('Linked servers: showing 1 of 200; use --links for the full list', MSSQLAudit().explain({'linked servers': links}))
        grants = {'visible directory grants': '200', 'ONE [READ]': '/one'}
        self.assertEqual(OracleAudit().explain({'directory grants': grants}), ['Directory grants: showing 1 of 200'])

    def test_only_observed_settings_are_listed_once(self):
        from plugins.dbms.mysql.audit import Audit as MySQLAudit
        def getValue(query, **kwargs):
            if '@@GLOBAL.secure_file_priv' in query:
                return [['secure_file_priv', 'V/allowed/']]
            return [['local_infile', 'VOFF']]
        inject.getValue = getValue
        result = MySQLAudit().getAudit()
        self.assertFalse(any('super_read_only' in item for item in result))
        self.assertEqual(sum('/ secure_file_priv:' in item for item in result), 1)
        self.assertFalse(any('not established' in item or 'does not establish' in item for item in result))

    def test_snippets_are_single_read_only_statements(self):
        for dbms in (DBMS.MYSQL, DBMS.PGSQL, DBMS.MSSQL, DBMS.ORACLE):
            set_dbms(dbms)
            audit = importlib.import_module('plugins.dbms.%s.audit' % DBMS_DIRECTORY_DICT[dbms]).Audit()
            for scope, snippets in audit.queries:
                for snippet in snippets:
                    sql = getSQLSnippet(dbms, snippet, LIMIT="20")
                    self.assertTrue(sql.startswith('SELECT '))
                    self.assertNotIn(';', sql.replace('; RPC out: ', ''))
                    self.assertIn('audit_value', sql)

    def test_help_is_one_line(self):
        output = subprocess.check_output([sys.executable, os.path.join(paths.SQLMAP_ROOT_PATH, 'sqlmap.py'), '-hh'])
        lines = [line for line in output.decode('utf-8').splitlines() if '--audit' in line]
        self.assertEqual(len(lines), 1)
        self.assertLessEqual(len(lines[0]), 78)
