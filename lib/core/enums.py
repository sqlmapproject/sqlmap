#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

class PRIORITY:
    LOWEST  = -100
    LOWER   = -50
    LOW     = -10
    NORMAL  = 0
    HIGH    = 10
    HIGHER  = 50
    HIGHEST = 100

class DBMS:
    MYSQL       = "MySQL"
    ORACLE      = "Oracle"
    POSTGRESQL  = "PostgreSQL"
    MSSQL       = "Microsoft SQL Server"
    SQLITE      = "SQLite"
    ACCESS      = "Microsoft Access"
    FIREBIRD    = "Firebird"
    MAXDB       = "SAP MaxDB"
    SYBASE      = "Sybase"

class PLACE:
    GET     = "GET"
    POST    = "POST"
    URI     = "URI"
    COOKIE  = "Cookie"
    UA      = "User-Agent"

class HTTPMETHOD:
    GET     = "GET"
    POST    = "POST"
    HEAD    = "HEAD"

class NULLCONNECTION:
    HEAD    = "HEAD"
    RANGE   = "Range"

class HASH:
    MYSQL        = r'(?i)\A\*[0-9a-f]{40}\Z'
    MYSQL_OLD    = r'(?i)\A[0-9a-f]{16}\Z'
    POSTGRES     = r'(?i)\Amd5[0-9a-f]{32}\Z'
    MSSQL        = r'(?i)\A0x0100[0-9a-f]{8}[0-9a-f]{40}\Z'
    MSSQL_OLD    = r'(?i)\A0x0100[0-9a-f]{8}[0-9a-f]{80}\Z'
    ORACLE       = r'(?i)\As:[0-9a-f]{60}\Z'
    ORACLE_OLD   = r'(?i)\A[0-9a-f]{16}\Z'
    MD5_GENERIC  = r'(?i)\A[0-9a-f]{32}\Z'
    SHA1_GENERIC = r'(?i)\A[0-9a-f]{40}\Z'
