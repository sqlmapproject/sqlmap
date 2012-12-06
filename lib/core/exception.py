#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

class SqlmapCompressionException(Exception):
    pass

class SqlmapConnectionException(Exception):
    pass

class SqlmapDataException(Exception):
    pass

class SqlmapFilePathException(Exception):
    pass

class SqlmapGenericException(Exception):
    pass

class SqlmapMissingDependence(Exception):
    pass

class SqlmapMissingMandatoryOptionException(Exception):
    pass

class SqlmapMissingPrivileges(Exception):
    pass

class SqlmapNoneDataException(Exception):
    pass

class SqlmapNotVulnerableException(Exception):
    pass

class SqlmapSilentQuitException(Exception):
    pass

class SqlmapUserQuitException(Exception):
    pass

class SqlmapRegExprException(Exception):
    pass

class SqlmapSyntaxException(Exception):
    pass

class SqlmapThreadException(Exception):
    pass

class SqlmapUndefinedMethod(Exception):
    pass

class SqlmapUnsupportedDBMSException(Exception):
    pass

class SqlmapUnsupportedFeatureException(Exception):
    pass

class SqlmapValueException(Exception):
    pass

exceptionsTuple = (
                    SqlmapCompressionException,
                    SqlmapConnectionException,
                    SqlmapDataException,
                    SqlmapFilePathException,
                    SqlmapGenericException,
                    SqlmapMissingDependence,
                    SqlmapMissingMandatoryOptionException,
                    SqlmapNoneDataException,
                    SqlmapRegExprException,
                    SqlmapSyntaxException,
                    SqlmapUndefinedMethod,
                    SqlmapMissingPrivileges,
                    SqlmapNotVulnerableException,
                    SqlmapThreadException,
                    SqlmapUnsupportedDBMSException,
                    SqlmapUnsupportedFeatureException,
                    SqlmapValueException,
                  )
