#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re

from subprocess import PIPE
from subprocess import Popen as execute

def getRevisionNumber():
    """
    Returns abbreviated commit hash number as retrieved with "git rev-parse --short HEAD"
    """

    retVal = None
    filePath = None

    _ = os.path.dirname(__file__)
    while True:
        filePath = os.path.join(_, ".git/refs/heads/master").replace('/', os.path.sep)
        if os.path.exists(filePath):
            break
        else:
            filePath = None
            if _ == os.path.dirname(_):
                break
            else:
                _ = os.path.dirname(_)
    if filePath:
        with open(filePath, "r") as f:
            match = re.match(r"(?i)[0-9a-f]{32}", f.read())
            retVal = match.group(0) if match else None

    if not retVal:
        process = execute("git rev-parse --verify HEAD", shell=True, stdout=PIPE, stderr=PIPE)
        stdout, _ = process.communicate()
        match = re.search(r"(?i)[0-9a-f]{32}", stdout or "")
        retVal = match.group(0) if match else None

    return retVal[:7] if retVal else None
