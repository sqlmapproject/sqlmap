#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

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



from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.settings import SECONDS
from lib.request import inject


def timeTest():
    infoMsg  = "testing time based blind sql injection on parameter "
    infoMsg += "'%s'" % kb.injParameter
    logger.info(infoMsg)

    query    = queries[kb.dbms].timedelay % SECONDS
    timeTest = inject.goStacked(query, timeTest=True)

    if timeTest[0] == True:
        kb.timeTest = timeTest[1]
    else:
        kb.timeTest = False

    return kb.timeTest
