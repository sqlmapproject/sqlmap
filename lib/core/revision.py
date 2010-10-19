#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re

from subprocess import PIPE
from subprocess import Popen as execute

def getRevisionNumber():
    curDir = os.path.dirname(os.path.realpath(__file__))
    retVal = None

    try:
        import pysvn

        client = pysvn.Client()
        if client.info(curDir):
            retVal = client.info(curDir).revision.number
    except ImportError, _:
        process = execute("svn info %s" % curDir, shell=True, stdout=PIPE, stderr=PIPE)
        svnStdout, svnStderr = process.communicate()

        if svnStdout:
            revision = re.search("Revision:\s+([\d]+)", svnStdout)

            if revision:
                retVal = revision.group(1)

    if retVal:
        try:
            retVal = int(retVal)
        except ValueError:
            retVal = None

    return retVal
