#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    line = payload.encode("hex")
    n = 2
    groups = [line[i:i+n] for i in range(0, len(line), n)]
    full = ''
    for x in groups:
        full = full + "\u00" + x
    retVal = full
    return retVal
