#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
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
                               "list":              "string",
                               "requestFile":       "string",
                               "googleDork":        "string",
                               "configFile":        "string"
                             },

            "Request":       {
                               "data":              "string",
                               "cookie":            "string",
                               "cookieUrlencode":   "boolean",
                               "dropSetCookie":     "boolean",
                               "agent":             "string",
                               "randomAgent":       "boolean",
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
                               "saFreq":            "integer"
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
                               "prefix":            "string",
                               "suffix":            "string",
                               "tamper":            "string"
                             },

            "Detection":     {
                               "level":             "integer",
                               "risk":              "integer",
                               "string":            "string",
                               "regexp":            "string",
                               "textOnly":          "boolean"
                             },

            "Techniques":    {
                               "timeSec":           "integer",
                               "uCols":             "string",
                               "uChar":             "string"
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
                               "sqlShell":          "boolean",
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
                               "xmlFile":           "string",
                               "sessionFile":       "string",
                               "trafficFile":       "string",
                               "flushSession":      "boolean",
                               "forms":             "boolean",
                               "eta":               "boolean",
                               "updateAll":         "boolean",
                               "batch":             "boolean"
                             },

            "Miscellaneous": {
                               "beep":              "boolean",
                               "checkPayload":      "boolean",
                               "cleanup":           "boolean",
                               "googlePage":        "integer",
                               "replicate":         "boolean",
                               "verbose":           "integer"
                             },
          }
