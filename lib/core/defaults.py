#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.datatype import AttribDict

_defaults =  {
               "timeSec":      5,
               "googlePage":   1,
               "cpuThrottle":  5,
               "verbose":      1,
               "cDel":         ";",
               "delay":        0,
               "timeout":      30,
               "retries":      3,
               "saFreq":       0,
               "threads":      1,
               "level":        1,
               "risk":         1,
               "tech":         "BEUST"
             }

defaults = AttribDict(_defaults)
