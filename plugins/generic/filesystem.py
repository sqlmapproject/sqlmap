#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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



from lib.core.exception import sqlmapUnsupportedFeatureException


class Filesystem:
    """
    This class defines generic OS file system functionalities for plugins.
    """

    def readFile(self, rFile):
        errMsg = "OS file reading not yet implemented for this DBMS"
        raise sqlmapUnsupportedFeatureException, errMsg


    def writeFile(self, wFile):
        errMsg = "OS file writing not yet implemented for this DBMS"
        raise sqlmapUnsupportedFeatureException, errMsg
