#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import sqlmapDataException

class advancedDict(dict):
    """
    This class defines the sqlmap object, inheriting from Python data
    type dictionary.
    """

    def __init__(self, indict=None, attribute=None):
        if indict is None:
            indict = {}

        # Set any attributes here - before initialisation
        # these remain as normal attributes
        self.attribute = attribute
        dict.__init__(self, indict)
        self.__initialised = True

        # After initialisation, setting attributes
        # is the same as setting an item

    def __getattr__(self, item):
        """
        Maps values to attributes
        Only called if there *is NOT* an attribute with this name
        """

        try:
            return self.__getitem__(item)
        except KeyError:
            raise sqlmapDataException, "unable to access item '%s'" % item

    def __setattr__(self, item, value):
        """
        Maps attributes to values
        Only if we are initialised
        """

        # This test allows attributes to be set in the __init__ method
        if not self.__dict__.has_key('_advancedDict__initialised'):
            return dict.__setattr__(self, item, value)

        # Any normal attributes are handled normally
        elif self.__dict__.has_key(item):
            dict.__setattr__(self, item, value)

        else:
            self.__setitem__(item, value)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, dict):
        self.__dict__ = dict

def injectionDict():
    injection = advancedDict()

    injection.place = None
    injection.parameter = None
    injection.ptype = None
    injection.prefix = None
    injection.suffix = None
    injection.clause = None

    # data is a dict with stype as key and a tuple as value with
    # title, where, comment and reqPayload
    injection.data = advancedDict()

    injection.dbms = None
    injection.dbms_version = None
    injection.os = None

    return injection
