#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.settings import PLATFORM
from lib.core.settings import PYVERSION
from lib.core.settings import VERSION
from lib.core.settings import REVISION
from lib.core.settings import VERSION_STRING


class sqlmapConnectionException(Exception):
    pass

class sqlmapDataException(Exception):
    pass

class sqlmapEndSAXParsing(Exception):
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
    errMsg  = "unhandled exception in %s, retry your " % VERSION_STRING
    errMsg += "run with the latest development version from the Subversion "
    errMsg += "repository. If the exception persists, please send by e-mail "
    errMsg += "to sqlmap-users@lists.sourceforge.net the command line, the "
    errMsg += "following text and any information needed to reproduce the "
    errMsg += "bug. The developers will try to reproduce the bug, fix it "
    errMsg += "accordingly and get back to you.\n"
    errMsg += "sqlmap version: %s%s\n" % (VERSION, " (r%d)" % REVISION if REVISION else "")
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
