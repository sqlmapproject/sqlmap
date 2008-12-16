#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

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
                               "url":               "string",
                               "list":              "string",
                               "googleDork":        "string",
                             },

            "Request":       {
                               "method":            "string",
                               "data":              "string",
                               "cookie":            "string",
                               "referer":           "string",
                               "agent":             "string",
                               "userAgentsFile":    "string",
                               "headers":           "string",
                               "aType":             "string",
                               "aCred":             "string",
                               "proxy":             "string",
                               "threads":           "integer",
                               "delay":             "float",
                               "timeout":           "float",
                             },

            "Injection":     {
                               "testParameter":     "string",
                               "dbms":              "string",
                               "prefix":            "string",
                               "postfix":           "string",
                               "string":            "string",
                               "regexp":            "string",
                               "eString":           "string",
                               "eRegexp":           "string",
                             },

            "Techniques":    {
                               "stackedTest":       "boolean",
                               "timeTest":          "boolean",
                               "unionTest":         "boolean",
                               "unionUse":          "boolean",
                             },

            "Fingerprint":   {
                               "extensiveFp":       "boolean",
                             },

            "Enumeration":   {
                               "getBanner":         "boolean",
                               "getCurrentUser":    "boolean",
                               "getCurrentDb":      "boolean",
                               "getUsers":          "boolean",
                               "getPasswordHashes": "boolean",
                               "getPrivileges":     "boolean",
                               "getDbs":            "boolean",
                               "getTables":         "boolean",
                               "getColumns":        "boolean",
                               "dumpTable":         "boolean",
                               "dumpAll":           "boolean",
                               "user":              "string",
                               "db":                "string",
                               "tbl":               "string",
                               "col":               "string",
                               "excludeSysDbs":     "boolean",
                               "limitStart":        "integer",
                               "limitStop":         "integer",
                               "query":             "string",
                               "sqlShell":          "boolean",
                             },

            "File system":   {
                               "rFile":             "string",
                               "wFile":             "string",
                             },

            "Takeover":      {
                               "osShell":           "boolean",
                             },

            "Miscellaneous": {
                               "eta":               "boolean",
                               "verbose":           "integer",
                               "updateAll":         "boolean",
                               "sessionFile":       "string",
                               "batch":             "boolean",
                             },
          }
