#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

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

import time

from lib.core.common import getDelayQuery
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.session import setStacked
from lib.request import inject

def stackedTest():
    if conf.direct:
        return

    if kb.stackedTest is not None:
        return kb.stackedTest

    infoMsg  = "testing stacked queries support on parameter "
    infoMsg += "'%s'" % kb.injParameter
    logger.info(infoMsg)

    query      = getDelayQuery()
    start      = time.time()
    payload, _ = inject.goStacked(query)
    duration   = int(time.time() - start)

    if duration >= conf.timeSec:
        infoMsg  = "the web application supports stacked queries "
        infoMsg += "on parameter '%s'" % kb.injParameter
        logger.info(infoMsg)

        kb.stackedTest = payload
    else:
        warnMsg  = "the web application does not support stacked queries "
        warnMsg += "on parameter '%s'" % kb.injParameter
        logger.warn(warnMsg)

        kb.stackedTest = False

    setStacked()

    return kb.stackedTest
