#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.datatype import AttribDict

_defaults =  {
               "csvDel":       ",",
               "timeSec":      5,
               "googlePage":   1,
               "cpuThrottle":  5,
               "verbose":      1,
               "delay":        0,
               "timeout":      30,
               "retries":      3,
               "saFreq":       0,
               "threads":      1,
               "level":        1,
               "risk":         1,
               "tech":         "BEUST",
               "torType":      "HTTP"
             }

defaults = AttribDict(_defaults)
