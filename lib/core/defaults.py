#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.datatype import advancedDict

_defaults =  {
               "timeSec":      5,
               "googlePage":   1,
               "cpuThrottle":  10,
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

defaults = advancedDict(_defaults)
