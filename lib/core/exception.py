#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
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

class sqlmapMissingDependence(Exception):
    pass

class sqlmapMissingMandatoryOptionException(Exception):
    pass

class sqlmapMissingPrivileges(Exception):
    pass

class sqlmapNoneDataException(Exception):
    pass

class sqlmapNotVulnerableException(Exception):
    pass

class sqlmapSilentQuitException(Exception):
    pass

class sqlmapUserQuitException(Exception):
    pass

class sqlmapRegExprException(Exception):
    pass

class sqlmapSyntaxException(Exception):
    pass

class sqlmapThreadException(Exception):
    pass

class sqlmapUndefinedMethod(Exception):
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
                    sqlmapMissingDependence,
                    sqlmapMissingMandatoryOptionException,
                    sqlmapNoneDataException,
                    sqlmapSilentQuitException,
                    sqlmapUserQuitException,
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