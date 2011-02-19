#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
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
