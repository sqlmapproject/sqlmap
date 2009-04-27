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



from lib.core.settings import PLATFORM
from lib.core.settings import PYVERSION
from lib.core.settings import VERSION
from lib.core.settings import VERSION_STRING


class sqlmapConnectionException(Exception):
    pass


class sqlmapDataException(Exception):
    pass


class sqlmapFilePathException(Exception):
    pass


class sqlmapGenericException(Exception):
    pass


class sqlmapMissingMandatoryOptionException(Exception):
    pass


class sqlmapNoneDataException(Exception):
    pass


class sqlmapRegExprException(Exception):
    pass


class sqlmapSyntaxException(Exception):
    pass


class sqlmapUndefinedMethod(Exception):
    pass


class sqlmapMissingPrivileges(Exception):
    pass


class sqlmapNotVulnerableException(Exception):
    pass


class sqlmapThreadException(Exception):
    pass


class sqlmapUnsupportedDBMSException(Exception):
    pass


class sqlmapUnsupportedFeatureException(Exception):
    pass


class sqlmapValueException(Exception):
    pass


def unhandledException():
    errMsg  = "unhandled exception in %s, please copy " % VERSION_STRING
    errMsg += "the command line and the following text and send by e-mail "
    errMsg += "to sqlmap-users@lists.sourceforge.net. The developer will "
    errMsg += "fix it as soon as possible:\nsqlmap version: %s\n" % VERSION
    errMsg += "Python version: %s\n" % PYVERSION
    errMsg += "Operating system: %s" % PLATFORM
    return errMsg


exceptionsTuple = (
                    sqlmapConnectionException,
                    sqlmapDataException,
                    sqlmapFilePathException,
                    sqlmapGenericException,
                    sqlmapMissingMandatoryOptionException,
                    sqlmapNoneDataException,
                    sqlmapRegExprException,
                    sqlmapSyntaxException,
                    sqlmapUndefinedMethod,
                    sqlmapMissingPrivileges,
                    sqlmapNotVulnerableException,
                    sqlmapThreadException,
                    sqlmapUnsupportedDBMSException,
                    sqlmapUnsupportedFeatureException,
                    sqlmapValueException,
                  )
