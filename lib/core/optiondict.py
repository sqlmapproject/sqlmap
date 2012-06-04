#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

optDict = {
            # Format:
            # Family:        { "parameter name":    "parameter datatype" },
            # Or:
            # Family:        { "parameter name":    ("parameter datatype", "category name used for common outputs feature") },
            "Target":        {
                               "direct":            "string",
                               "url":               "string",
                               "logFile":           "string",
                               "bulkFile":          "string",
                               "requestFile":       "string",
                               "googleDork":        "string",
                               "configFile":        "string"
                             },

            "Request":       {
                               "data":              "string",
                               "pDel":              "string",
                               "cookie":            "string",
                               "loC":               "string",
                               "cookieUrlencode":   "boolean",
                               "dropSetCookie":     "boolean",
                               "agent":             "string",
                               "randomAgent":       "boolean",
                               "rParam":            "string",
                               "forceSSL":          "boolean",
                               "host":              "string",
                               "referer":           "string",
                               "headers":           "string",
                               "aType":             "string",
                               "aCred":             "string",
                               "aCert":             "string",
                               "proxy":             "string",
                               "pCred":             "string",
                               "ignoreProxy":       "boolean",
                               "delay":             "float",
                               "timeout":           "float",
                               "retries":           "integer",
                               "scope":             "string",
                               "safUrl":            "string",
                               "saFreq":            "integer",
                               "skipUrlEncode":     "boolean",
                               "evalCode":          "string"
                             },

            "Optimization":  {
                               "optimize":          "boolean",
                               "predictOutput":     "boolean",
                               "keepAlive":         "boolean",
                               "nullConnection":    "boolean",
                               "threads":           "integer"
                             },

            "Injection":     {
                               "testParameter":     "string",
                               "dbms":              "string",
                               "os":                "string",
                               "invalidBignum":     "boolean",
                               "invalidLogical":     "boolean",
                               "prefix":            "string",
                               "suffix":            "string",
                               "skip":              "string",
                               "tamper":            "string"
                             },

            "Detection":     {
                               "level":             "integer",
                               "risk":              "integer",
                               "string":            "string",
                               "regexp":            "string",
                               "code":              "integer",
                               "textOnly":          "boolean",
                               "titles":            "boolean"
                             },

            "Techniques":    {
                               "tech":              "string",
                               "timeSec":           "integer",
                               "uCols":             "string",
                               "uChar":             "string",
                               "dName":             "string"
                             },

            "Fingerprint":   {
                               "extensiveFp":       "boolean"
                             },

            "Enumeration":   {
                               "getBanner":         ("boolean", "Banners"),
                               "getCurrentUser":    ("boolean", "Users"),
                               "getCurrentDb":      ("boolean", "Databases"),
                               "isDba":             "boolean",
                               "getUsers":          ("boolean", "Users"),
                               "getPasswordHashes": ("boolean", "Passwords"),
                               "getPrivileges":     ("boolean", "Privileges"),
                               "getRoles":          ("boolean", "Roles"),
                               "getDbs":            ("boolean", "Databases"),
                               "getTables":         ("boolean", "Tables"),
                               "getColumns":        ("boolean", "Columns"),
                               "getSchema":         "boolean",
                               "getCount":          "boolean",
                               "dumpTable":         "boolean",
                               "dumpAll":           "boolean",
                               "search":            "boolean",
                               "db":                "string",
                               "tbl":               "string",
                               "col":               "string",
                               "user":              "string",
                               "excludeSysDbs":     "boolean",
                               "limitStart":        "integer",
                               "limitStop":         "integer",
                               "firstChar":         "integer",
                               "lastChar":          "integer",
                               "query":             "string",
                               "sqlShell":          "boolean"
                             },

            "Brute":         {
                               "commonTables":       "boolean",
                               "commonColumns":      "boolean"
                             },

            "User-defined function": {
                               "udfInject":         "boolean",
                               "shLib":             "string"
                             },

            "File system":   {
                               "rFile":             "string",
                               "wFile":             "string",
                               "dFile":             "string"
                             },

            "Takeover":      {
                               "osCmd":             "string",
                               "osShell":           "boolean",
                               "osPwn":             "boolean",
                               "osSmb":             "boolean",
                               "osBof":             "boolean",
                               "privEsc":           "boolean",
                               "msfPath":           "string",
                               "tmpPath":           "string"
                             },

            "Windows":       {
                               "regRead":           "boolean",
                               "regAdd":            "boolean",
                               "regDel":            "boolean",
                               "regKey":            "string",
                               "regVal":            "string",
                               "regData":           "string",
                               "regType":           "string"
                             },

            "General":       {
                               #"xmlFile":           "string",
                               "sessionFile":       "string",
                               "trafficFile":       "string",
                               "batch":             "boolean",
                               "charset":           "string",
                               "checkTor":          "boolean",
                               "crawlDepth":        "integer",
                               "csvDel":            "string",
                               "eta":               "boolean",
                               "flushSession":      "boolean",
                               "forms":             "boolean",
                               "freshQueries":      "boolean",
                               "hexConvert":        "boolean",
                               "parseErrors":       "boolean",
                               "replicate":         "boolean",
                               "updateAll":         "boolean",
                               "tor":               "boolean",
                               "torPort":           "integer",
                               "torType":           "string",
                             },

            "Miscellaneous": {
                               "beep":              "boolean",
                               "checkPayload":      "boolean",
                               "cleanup":           "boolean",
                               "dependencies":      "boolean",
                               "exact":             "boolean",
                               "googlePage":        "integer",
                               "mobile":            "boolean",
                               "pageRank":          "boolean",
                               "smart":             "boolean",
                               "wizard":            "boolean",
                               "verbose":           "integer"
                             },
          }
