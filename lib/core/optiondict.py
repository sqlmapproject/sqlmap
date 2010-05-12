#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

optDict = {
            # Family:        { "parameter_name":    "parameter_datatype" },
            "Target":        {
                               "direct":            "string",
                               "url":               "string",
                               "list":              "string",
                               "requestFile":       "string",
                               "googleDork":        "string",
                               "configFile":        "string"
                             },

            "Request":       {
                               "method":            "string",
                               "data":              "string",
                               "cookie":            "string",
                               "cookieUrlencode":   "boolean",
                               "dropSetCookie":     "boolean",
                               "referer":           "string",
                               "agent":             "string",
                               "userAgentsFile":    "string",
                               "headers":           "string",
                               "aType":             "string",
                               "aCred":             "string",
                               "aCert":             "string",
                               "proxy":             "string",
                               "ignoreProxy":       "boolean",
                               "threads":           "integer",
                               "delay":             "float",
                               "timeout":           "float",
                               "retries":           "integer",
                               "scope":             "string",
                               "safUrl":            "string",
                               "saFreq":            "integer"
                             },

            "Injection":     {
                               "testParameter":     "string",
                               "dbms":              "string",
                               "os":                "string",
                               "prefix":            "string",
                               "postfix":           "string",
                               "string":            "string",
                               "regexp":            "string",
                               "eString":           "string",
                               "eRegexp":           "string",
                               "useBetween":        "boolean",
                             },

            "Techniques":    {
                               "stackedTest":       "boolean",
                               "timeTest":          "boolean",
                               "timeSec":           "integer",
                               "unionTest":         "boolean",
                               "uTech":             "string",
                               "unionUse":          "boolean"
                             },

            "Fingerprint":   {
                               "extensiveFp":       "boolean"
                             },

            "Enumeration":   {
                               "getBanner":         "boolean",
                               "getCurrentUser":    "boolean",
                               "getCurrentDb":      "boolean",
                               "isDba":             "boolean",
                               "getUsers":          "boolean",
                               "getPasswordHashes": "boolean",
                               "getPrivileges":     "boolean",
                               "getRoles":          "boolean",
                               "getDbs":            "boolean",
                               "getTables":         "boolean",
                               "getColumns":        "boolean",
                               "dumpTable":         "boolean",
                               "dumpAll":           "boolean",
                               "search":            "boolean",
                               "user":              "string",
                               "db":                "string",
                               "tbl":               "string",
                               "col":               "string",
                               "excludeSysDbs":     "boolean",
                               "limitStart":        "integer",
                               "limitStop":         "integer",
                               "firstChar":         "integer",
                               "lastChar":          "integer",
                               "query":             "string",
                               "sqlShell":          "boolean"
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

            "Miscellaneous": {
                               "sessionFile":       "string",
                               "flushSession":      "boolean",
                               "eta":               "boolean",
                               "googlePage":        "integer",
                               "updateAll":         "boolean",
                               "batch":             "boolean",
                               "cleanup":           "boolean",
                               "verbose":           "integer"
                             },
          }
