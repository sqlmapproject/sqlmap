#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

firebirdTypes = {
                    "261":"BLOB",
                    "14":"CHAR",
                    "40":"CSTRING",
                    "11":"D_FLOAT",
                    "27":"DOUBLE",
                    "10":"FLOAT",
                    "16":"INT64",
                    "8":"INTEGER",
                    "9":"QUAD",
                    "7":"SMALLINT",
                    "12":"DATE",
                    "13":"TIME",
                    "35":"TIMESTAMP",
                    "37":"VARCHAR"
                }

sybaseTypes   = {
                    "14":"floatn",
                    "8":"float",
                    "15":"datetimn",
                    "12":"datetime",
                    "23":"real",
                    "28":"numericn",
                    "10":"numeric",
                    "27":"decimaln",
                    "26":"decimal",
                    "17":"moneyn",
                    "11":"money",
                    "21":"smallmoney",
                    "22":"smalldatetime",
                    "13":"intn",
                    "7":"int",
                    "6":"smallint",
                    "5":"tinyint",
                    "16":"bit",
                    "2":"varchar",
                    "18":"sysname",
                    "25":"nvarchar",
                    "1":"char",
                    "24":"nchar",
                    "4":"varbinary",
                    "80":"timestamp",
                    "3":"binary",
                    "19":"text",
                    "20":"image",
                }

mysqlPrivs    = {
                    1:"select_priv",
                    2:"insert_priv",
                    3:"update_priv",
                    4:"delete_priv",
                    5:"create_priv",
                    6:"drop_priv",
                    7:"reload_priv",
                    8:"shutdown_priv",
                    9:"process_priv",
                    10:"file_priv",
                    11:"grant_priv",
                    12:"references_priv",
                    13:"index_priv",
                    14:"alter_priv",
                    15:"show_db_priv",
                    16:"super_priv",
                    17:"create_tmp_table_priv",
                    18:"lock_tables_priv",
                    19:"execute_priv",
                    20:"repl_slave_priv",
                    21:"repl_client_priv",
                    22:"create_view_priv",
                    23:"show_view_priv",
                    24:"create_routine_priv",
                    25:"alter_routine_priv",
                    26:"create_user_priv",
                }

pgsqlPrivs    = {
                    1:"createdb",
                    2:"super",
                    3:"catupd",
                }

firebirdPrivs = {
                    "S": "SELECT",
                    "I": "INSERT",
                    "U": "UPDATE",
                    "D": "DELETE",
                    "R": "REFERENCES",
                    "E": "EXECUTE"
                }
