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

from lib.core.agent import agent
from lib.core.data import conf
from lib.core.data import kb
from lib.core.settings import SQL_STATEMENTS
from lib.utils.timeout import timeout

def direct(query, content=True):
    output = None
    select = False
    query = agent.payloadDirect(query)

    if kb.dbms == "Oracle" and query.startswith("SELECT ") and " FROM " not in query:
        query = "%s FROM DUAL" % query

    for sqlTitle, sqlStatements in SQL_STATEMENTS.items():
        for sqlStatement in sqlStatements:
            if query.lower().startswith(sqlStatement) and sqlTitle == "SQL SELECT statement":
                select = True
                break

    if select:
        output = timeout(func=conf.dbmsConnector.select, args = query, duration=conf.timeout, default=None)
    else:
        output = timeout(func=conf.dbmsConnector.execute, args = query, duration=conf.timeout, default=None)

    if output is None or len(output) == 0:
        return None
    elif content:
        if len(output) == 1:
            if len(output[0]) == 1:
                return str(list(output)[0][0])
            else:
                return list(output)
        else:
            return output
    else:
        for line in output:
            if line[0] in (1, -1):
                return True
            else:
                return False
