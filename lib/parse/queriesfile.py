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



from xml.sax import parse
from xml.sax.handler import ContentHandler

from lib.core.common import checkFile
from lib.core.common import sanitizeStr
from lib.core.data import logger
from lib.core.data import queries
from lib.core.data import paths
from lib.core.datatype import advancedDict


class queriesHandler(ContentHandler):
    """
    This class defines methods to parse the default DBMS queries
    from an XML file
    """

    def __init__(self):
        self.__dbms    = ''
        self.__queries = advancedDict()


    def startElement(self, name, attrs):
        if name == "dbms":
            data = sanitizeStr(attrs.get("value"))
            self.__dbms = data

        elif name == "cast":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.cast = data

        elif name == "length":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.length = data

        elif name == "isnull":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.isnull = data

        elif name == "delimiter":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.delimiter = data

        elif name == "limit":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.limit = data

        elif name == "limitregexp":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.limitregexp = data

        elif name == "limitgroupstart":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.limitgroupstart = data

        elif name == "limitgroupstop":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.limitgroupstop = data

        elif name == "limitstring":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.limitstring = data

        elif name == "order":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.order = data

        elif name == "count":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.count = data

        elif name == "comment":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.comment = data

        elif name == "timedelay":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.timedelay = data

        elif name == "substring":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.substring = data

        elif name == "case":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.case = data

        elif name == "inference":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.inference = data

        elif name == "banner":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.banner = data

        elif name == "current_user":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.currentUser = data

        elif name == "current_db":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.currentDb = data

        elif name == "is_dba":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.isDba = data

        elif name == "inband":
            self.__inband    = sanitizeStr(attrs.get("query"))
            self.__inband2   = sanitizeStr(attrs.get("query2"))
            self.__condition = sanitizeStr(attrs.get("condition"))
            self.__condition2 = sanitizeStr(attrs.get("condition2"))

        elif name == "blind":
            self.__blind  = sanitizeStr(attrs.get("query"))
            self.__blind2 = sanitizeStr(attrs.get("query2"))
            self.__count  = sanitizeStr(attrs.get("count"))
            self.__count2 = sanitizeStr(attrs.get("count2"))


    def endElement(self, name):
        if name == "dbms":
            queries[self.__dbms] = self.__queries
            self.__queries = advancedDict()

        elif name == "users":
            self.__users = {}
            self.__users["inband"] = { "query": self.__inband, "query2": self.__inband2 }
            self.__users["blind"]  = { "query": self.__blind, "query2": self.__blind2,
                                       "count": self.__count, "count2": self.__count2 }

            self.__queries.users = self.__users

        elif name == "passwords":
            self.__passwords = {}
            self.__passwords["inband"] = { "query": self.__inband, "query2": self.__inband2, "condition": self.__condition }
            self.__passwords["blind"]  = { "query": self.__blind, "query2": self.__blind2,
                                           "count": self.__count, "count2": self.__count2 }

            self.__queries.passwords = self.__passwords

        elif name == "privileges":
            self.__privileges = {}
            self.__privileges["inband"] = { "query": self.__inband, "query2": self.__inband2, "condition": self.__condition, "condition2": self.__condition2 }
            self.__privileges["blind"]  = { "query": self.__blind, "query2": self.__blind2,
                                           "count": self.__count, "count2": self.__count2 }

            self.__queries.privileges = self.__privileges

        elif name == "dbs":
            self.__dbs = {}
            self.__dbs["inband"] = { "query": self.__inband, "query2": self.__inband2 }
            self.__dbs["blind"]  = { "query": self.__blind, "query2": self.__blind2,
                                     "count": self.__count, "count2": self.__count2 }

            self.__queries.dbs = self.__dbs

        elif name == "tables":
            self.__tables = {}
            self.__tables["inband"] = { "query": self.__inband, "condition": self.__condition }
            self.__tables["blind"]  = { "query": self.__blind, "count": self.__count }

            self.__queries.tables = self.__tables

        elif name == "columns":
            self.__columns = {}
            self.__columns["inband"] = { "query": self.__inband }
            self.__columns["blind"]  = { "query": self.__blind, "query2": self.__blind2, "count": self.__count }

            self.__queries.columns = self.__columns

        elif name == "dump_table":
            self.__dumpTable = {}
            self.__dumpTable["inband"] = { "query": self.__inband }
            self.__dumpTable["blind"]  = { "query": self.__blind, "count": self.__count }

            self.__queries.dumpTable = self.__dumpTable


def queriesParser():
    """
    This function calls a class to parse the default DBMS queries
    from an XML file
    """

    debugMsg = "parsing XML queries file"
    logger.debug(debugMsg)

    xmlfile = paths.QUERIES_XML

    checkFile(xmlfile)
    handler = queriesHandler()
    parse(xmlfile, handler)
