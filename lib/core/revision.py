#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import re
import subprocess

def getRevisionNumber():
    """
    Returns abbreviated commit hash number as retrieved with "git rev-parse --short HEAD"
    """

    retVal = None
    filePath = None
    _ = os.path.dirname(__file__)

    while True:
        filePath = os.path.join(_, ".git", "HEAD")
        if os.path.exists(filePath):
            break
        else:
            filePath = None
            if _ == os.path.dirname(_):
                break
            else:
                _ = os.path.dirname(_)

    while True:
        if filePath and os.path.isfile(filePath):
            with open(filePath, "r") as f:
                content = f.read()
                filePath = None
                if content.startswith("ref: "):
                    filePath = os.path.join(_, ".git", content.replace("ref: ", "")).strip()
                else:
                    match = re.match(r"(?i)[0-9a-f]{32}", content)
                    retVal = match.group(0) if match else None
                    break
        else:
            break

    if not retVal:
        process = subprocess.Popen("git rev-parse --verify HEAD", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = process.communicate()
        match = re.search(r"(?i)[0-9a-f]{32}", stdout or "")
        retVal = match.group(0) if match else None

    return retVal[:7] if retVal else None
