#!/usr/bin/env python
"""Create test accounts and known grants only in the disposable audit databases."""
import time
from db import connect, engine

admin = {'mysql': 'root', 'mariadb': 'root', 'postgres': 'postgres', 'mssql': 'sa', 'oracle': 'sys'}[engine]
for attempt in range(120):
    try:
        conn = connect(admin)
        break
    except Exception:
        if attempt == 119:
            raise
        time.sleep(1)
cursor = conn.cursor()


def execute(sql):
    cursor.execute(sql)


if engine in ('mysql', 'mariadb'):
    execute('CREATE TABLE users (id INT PRIMARY KEY,name VARCHAR(100),surname VARCHAR(100))')
    for user in ('audit_app', 'audit_limited'):
        execute("CREATE USER '%s'@'%%' IDENTIFIED BY 'AuditOnly!2026'" % user)
        execute("GRANT SELECT ON auditlab.* TO '%s'@'%%'" % user)
    execute("GRANT SELECT ON performance_schema.* TO 'audit_app'@'%'")
    execute("GRANT FILE ON *.* TO 'audit_app'@'%'")
elif engine == 'postgres':
    execute('CREATE TABLE users (id INT PRIMARY KEY,name VARCHAR(100),surname VARCHAR(100))')
    for user in ('audit_app', 'audit_limited'):
        execute("CREATE USER %s WITH PASSWORD 'AuditOnly!2026'" % user)
        execute('GRANT SELECT ON users TO %s' % user)
    execute('GRANT pg_read_server_files TO audit_app')
    execute('GRANT pg_write_server_files TO audit_app')
    execute("ALTER ROLE audit_app SET row_security=off")
elif engine == 'mssql':
    execute('CREATE TABLE users (id INT PRIMARY KEY,name VARCHAR(100),surname VARCHAR(100))')
    for user in ('audit_app', 'audit_limited'):
        execute("CREATE LOGIN %s WITH PASSWORD='AuditOnly!2026',CHECK_POLICY=OFF" % user)
        execute('CREATE USER %s FOR LOGIN %s' % (user,user))
        execute('GRANT SELECT ON users TO %s' % user)
    execute('DENY SELECT ON OBJECT::sys.configurations TO audit_limited')
    execute('DENY SELECT ON OBJECT::sys.servers TO audit_limited')
    execute("EXEC sp_configure 'show advanced options',1")
    execute('RECONFIGURE')
    execute("EXEC sp_configure 'clr enabled',1")
    execute('RECONFIGURE')
    execute("EXEC sp_addlinkedserver @server=N'audit_reporting',@srvproduct=N'',@provider=N'MSOLEDBSQL',@datasrc=N'reporting.invalid'")
    execute("EXEC sp_serveroption @server=N'audit_reporting',@optname=N'rpc out',@optvalue=N'true'")
else:
    execute('GRANT DBA TO audit_owner')
    for user in ('audit_app', 'audit_limited'):
        execute('CREATE USER %s IDENTIFIED BY "AuditOnly!2026"' % user)
        execute('GRANT CREATE SESSION TO %s' % user)
    execute('CREATE TABLE audit_owner.users (id NUMBER PRIMARY KEY,name VARCHAR2(100),surname VARCHAR2(100))')
    for user in ('audit_app', 'audit_limited'):
        execute('GRANT SELECT ON audit_owner.users TO %s' % user)
        execute('CREATE SYNONYM %s.users FOR audit_owner.users' % user)
    execute('CREATE SYNONYM system.users FOR audit_owner.users')
    execute('GRANT SELECT ON sys.v_$parameter TO audit_app')
    execute("CREATE DIRECTORY AUDIT_FILES AS '/tmp/audit-files'")
    execute('GRANT READ ON DIRECTORY AUDIT_FILES TO audit_app')
    execute('CREATE SYNONYM audit_owner.audit_fixture_users FOR audit_owner.users')
    # Insert into the application schema; the SYS/SYSTEM account is only the fixture provisioner.
    execute("INSERT INTO audit_owner.users VALUES (1,'luther','blisset')")
    execute("INSERT INTO audit_owner.users VALUES (2,'fluffy','bunny')")
    conn.commit()
if engine != 'oracle':
    execute("INSERT INTO users VALUES (1,'luther','blisset')")
    execute("INSERT INTO users VALUES (2,'fluffy','bunny')")
conn.close()
print('%s fixture seeded' % engine)
