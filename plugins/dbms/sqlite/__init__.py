#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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

from lib.core.settings import SQLITE_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.sqlite.enumeration import Enumeration
from plugins.dbms.sqlite.filesystem import Filesystem
from plugins.dbms.sqlite.fingerprint import Fingerprint
from plugins.dbms.sqlite.syntax import Syntax
from plugins.dbms.sqlite.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class SQLiteMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines SQLite methods
    """

    def __init__(self):
        self.excludeDbsList = SQLITE_SYSTEM_DBS

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

        unescaper.setUnescape(SQLiteMap.unescape)
