#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
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
    except:
        pass

    if not retVal:
        # Reference: http://stackoverflow.com/questions/242295/how-does-one-add-a-svn-repository-build-number-to-python-code
        entriesPath = '%s/.svn/entries' % curDir

        if os.path.exists(entriesPath):
            entries = open(entriesPath, 'r').read()
            # Versions >= 7 of the entries file are flat text.  The first line is
            # the version number. The next set of digits after 'dir' is the revision.
            if re.match('(\d+)', entries):
                match = re.search('\d+\s+dir\s+(\d+)', entries)
                if match:
                    retVal = match.groups()[0]
            # Older XML versions of the file specify revision as an attribute of
            # the first entries node.
            else:
                from xml.dom import minidom
                dom = minidom.parse(entriesPath)
                retVal = dom.getElementsByTagName('entry')[0].getAttribute('revision')

    if retVal:
        try:
            retVal = int(retVal)
        except ValueError:
            retVal = None

    return retVal
