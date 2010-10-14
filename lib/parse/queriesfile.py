#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from xml.sax.handler import ContentHandler

from lib.core.common import checkFile
from lib.core.common import parseXmlFile
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

            data = sanitizeStr(attrs.get("query2"))
            self.__queries.timedelay2 = data

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

        elif name == "check_udf":
            data = sanitizeStr(attrs.get("query"))
            self.__queries.checkUdf = data

        elif name == "inband":
            self.__inband    = sanitizeStr(attrs.get("query"))
            self.__inband2   = sanitizeStr(attrs.get("query2"))
            self.__conditionInband = sanitizeStr(attrs.get("condition"))
            self.__conditionInband2 = sanitizeStr(attrs.get("condition2"))

        elif name == "blind":
            self.__blind  = sanitizeStr(attrs.get("query"))
            self.__blind2 = sanitizeStr(attrs.get("query2"))
            self.__count  = sanitizeStr(attrs.get("count"))
            self.__count2 = sanitizeStr(attrs.get("count2"))
            self.__conditionBlind = sanitizeStr(attrs.get("condition"))
            self.__conditionBlind2 = sanitizeStr(attrs.get("condition2"))

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
            self.__passwords["inband"] = { "query": self.__inband, "query2": self.__inband2, "condition": self.__conditionInband }
            self.__passwords["blind"]  = { "query": self.__blind, "query2": self.__blind2,
                                           "count": self.__count, "count2": self.__count2 }

            self.__queries.passwords = self.__passwords

        elif name == "privileges":
            self.__privileges = {}
            self.__privileges["inband"] = { "query": self.__inband, "query2": self.__inband2, "condition": self.__conditionInband, "condition2": self.__conditionInband2 }
            self.__privileges["blind"]  = { "query": self.__blind, "query2": self.__blind2,
                                           "count": self.__count, "count2": self.__count2 }

            self.__queries.privileges = self.__privileges

        elif name == "roles":
            self.__roles = {}
            self.__roles["inband"] = { "query": self.__inband, "query2": self.__inband2, "condition": self.__conditionInband, "condition2": self.__conditionInband2 }
            self.__roles["blind"]  = { "query": self.__blind, "query2": self.__blind2,
                                       "count": self.__count, "count2": self.__count2 }

            self.__queries.roles = self.__roles

        elif name == "dbs":
            self.__dbs = {}
            self.__dbs["inband"] = { "query": self.__inband, "query2": self.__inband2 }
            self.__dbs["blind"]  = { "query": self.__blind, "query2": self.__blind2,
                                     "count": self.__count, "count2": self.__count2 }

            self.__queries.dbs = self.__dbs

        elif name == "tables":
            self.__tables = {}
            self.__tables["inband"] = { "query": self.__inband, "condition": self.__conditionInband }
            self.__tables["blind"]  = { "query": self.__blind, "count": self.__count }

            self.__queries.tables = self.__tables

        elif name == "columns":
            self.__columns = {}
            self.__columns["inband"] = { "query": self.__inband, "condition": self.__conditionInband }
            self.__columns["blind"]  = { "query": self.__blind, "query2": self.__blind2, "count": self.__count, "condition": self.__conditionBlind }

            self.__queries.columns = self.__columns

        elif name == "dump_table":
            self.__dumpTable = {}
            self.__dumpTable["inband"] = { "query": self.__inband }
            self.__dumpTable["blind"]  = { "query": self.__blind, "count": self.__count }

            self.__queries.dumpTable = self.__dumpTable

        elif name == "search_db":
            self.__searchDb = {}
            self.__searchDb["inband"] = { "query": self.__inband, "query2": self.__inband2, "condition": self.__conditionInband, "condition2": self.__conditionInband2 }
            self.__searchDb["blind"]  = { "query": self.__blind, "query2": self.__blind2, "count": self.__count, "count2": self.__count2, "condition": self.__conditionBlind, "condition2": self.__conditionBlind2 }

            self.__queries.searchDb = self.__searchDb

        elif name == "search_table":
            self.__searchTable = {}
            self.__searchTable["inband"] = { "query": self.__inband, "query2": self.__inband2, "condition": self.__conditionInband, "condition2": self.__conditionInband2 }
            self.__searchTable["blind"]  = { "query": self.__blind, "query2": self.__blind2, "count": self.__count, "count2": self.__count2, "condition": self.__conditionBlind, "condition2": self.__conditionBlind2 }

            self.__queries.searchTable = self.__searchTable

        elif name == "search_column":
            self.__searchColumn = {}
            self.__searchColumn["inband"] = { "query": self.__inband, "query2": self.__inband2, "condition": self.__conditionInband, "condition2": self.__conditionInband2 }
            self.__searchColumn["blind"]  = { "query": self.__blind, "query2": self.__blind2, "count": self.__count, "count2": self.__count2, "condition": self.__conditionBlind, "condition2": self.__conditionBlind2 }

            self.__queries.searchColumn = self.__searchColumn

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
    parseXmlFile(xmlfile, handler)
