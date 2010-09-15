#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2010 Miroslav Stampar <miroslav.stampar@gmail.com>

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

import os
import sys

from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths

def smokeTest():
    """
    This will run the basic smoke testing of a program
    """
    import doctest
    retVal = True
    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        for file in files:
            if os.path.splitext(file)[1].lower() == '.py' and file != '__init__.py':
                path = os.path.join(root, os.path.splitext(file)[0])
                path = path.replace(paths.SQLMAP_ROOT_PATH, '.')
                path = path.replace(os.sep, '.').lstrip('.')
                try:
                    __import__(path)
                    module = sys.modules[path]
                except Exception, msg:
                    retVal = False
                    errMsg = "smoke test failed at importing module '%s' (%s):\n%s\n" % (path, os.path.join(paths.SQLMAP_ROOT_PATH, file), msg)
                    logger.error(errMsg)
                else:
                    # Run doc tests
                    # Reference: http://docs.python.org/library/doctest.html
                    (failure_count, test_count) = doctest.testmod(module)
                    if failure_count > 0:
                        retVal = False

    infoMsg = "smoke test "
    if retVal:
        infoMsg += "PASSED"
        logger.info(infoMsg)
    else:
        infoMsg += "FAILED"
        logger.error(infoMsg)
    return retVal

def liveTest():
    """
    This will run the test of a program against the live testing environment
    """
    pass
