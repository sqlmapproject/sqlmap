import os
import threading

engine = os.environ['ENGINE']
password = 'AuditOnly!2026'
host = os.environ.get('DB_HOST', engine)
pools = {}
poolLock = threading.Lock()


def connect(account, pooled=False):
    if engine in ('mysql', 'mariadb'):
        import pymysql
        return pymysql.connect(host=host, user=account, password=password, database='auditlab', autocommit=True)
    if engine == 'postgres':
        import psycopg
        return psycopg.connect(host=host, user=account, password=password, dbname='auditlab', autocommit=True)
    if engine == 'mssql':
        import pytds
        return pytds.connect(host, user=account, password=password, database='master', autocommit=True)
    import oracledb
    if pooled:
        with poolLock:
            if account not in pools:
                pools[account] = oracledb.create_pool(user=account, password=password, dsn=host+'/FREEPDB1', min=1, max=10, increment=1)
        return pools[account].acquire()
    return oracledb.connect(user=account, password=password, dsn=host+'/FREEPDB1', mode=oracledb.AUTH_MODE_SYSDBA if account == 'sys' else oracledb.AUTH_MODE_DEFAULT)
