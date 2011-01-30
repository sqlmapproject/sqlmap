#!/usr/bin/env python

import codecs
import os
import re
import xml

import xml.sax.saxutils as saxutils

from xml.dom.minidom import Document
from xml.parsers.expat import ExpatError

from extra.prettyprint import prettyprint
from lib.core.common import getUnicode
from lib.core.common import restoreDumpMarkedChars
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapFilePathException
from lib.core.settings import UNICODE_ENCODING

TECHNIC_ELEM_NAME = "Technic"
TECHNICS_ELEM_NAME = "Technics"
BANNER_ELEM_NAME = "Banner"
COLUMNS_ELEM_NAME = "DatabaseColumns"
COLUMN_ELEM_NAME = "Column"
CELL_ELEM_NAME = "Cell"
COLUMN_ATTR = "column"
ROW_ELEM_NAME = "Row"
TABLES_ELEM_NAME = "tables"
DATABASE_COLUMNS_ELEM = "DB"
DB_TABLES_ELEM_NAME = "DBTables"
DB_TABLE_ELEM_NAME = "DBTable"
IS_DBA_ELEM_NAME = "isDBA"
FILE_CONTENT_ELEM_NAME = "FileContent"
DB_ATTR = "db"
UNKNOWN_COLUMN_TYPE= "unknown"
USER_SETTINGS_ELEM_NAME = "UserSettings"
USER_SETTING_ELEM_NAME = "UserSetting"
USERS_ELEM_NAME = "Users"
USER_ELEM_NAME = "User"
DB_USER_ELEM_NAME = "DBUser"
SETTINGS_ELEM_NAME = "Settings"
DBS_ELEM_NAME = "DBs"
DB_NAME_ELEM_NAME = "DBName"
DATABASE_ELEM_NAME = "Database"
TABLE_ELEM_NAME = "Table"
DB_TABLE_VALUES_ELEM_NAME = "DBTableValues"
DB_VALUES_ELEM = "DBValues"
QUERIES_ELEM_NAME = "Queries"
QUERY_ELEM_NAME = "Query"
REGISTERY_ENTRIES_ELEM_NAME = "RegistryEntries"
REGISTER_DATA_ELEM_NAME = "RegisterData"
DEFAULT_DB = "All"
MESSAGE_ELEM = "Message"
MESSAGES_ELEM_NAME = "Messages"
ERROR_ELEM_NAME = "Error"
LST_ELEM_NAME = "List"
LSTS_ELEM_NAME = "Lists"
CURRENT_USER_ELEM_NAME = "CurrentUser"
CURRENT_DB_ELEM_NAME = "CurrentDB"
MEMBER_ELEM = "Member"
ADMIN_USER = "Admin"
REGULAR_USER = "User"
STATUS_ELEM_NAME = "Status"
RESULTS_ELEM_NAME = "Results"
UNHANDLED_PROBLEM_TYPE = "Unhandled"
NAME_ATTR = "name"
TYPE_ATTR = "type"
VALUE_ATTR = "value"
SUCESS_ATTR = "success"
NAME_SPACE_ATTR = 'http://www.w3.org/2001/XMLSchema-instance'
XMLNS_ATTR = "xmlns:xsi"
SCHEME_NAME = "sqlmap.xsd"
SCHEME_NAME_ATTR = "xsi:noNamespaceSchemaLocation"
CHARACTERS_TO_ENCODE = range(32) + range(127, 256)
ENTITIES  = {'"':'&quot;',"'":"&apos;"}

class XMLDump:
    '''
    This class purpose is to dump the data into an xml Format.
    The format of the xml file is described in the scheme file xml/sqlmap.xsd
    '''

    def __init__(self):
        self.__outputFile = None
        self.__outputFP   = None
        self.__root = None
        self.__doc = Document()

    def __addToRoot(self,element):
        '''
        Adds element to the root element
        '''
        self.__root.appendChild(element)

    def __write(self, data, n=True):
        '''
        Writes the data into the file
        '''
        if n:
            self.__outputFP.write("%s\n" % data)
        else:
            self.__outputFP.write("%s " % data)

        self.__outputFP.flush()

        conf.loggedToOut = True

    def __getRootChild(self,elemName):
        '''
        Returns the child of the root with the described name
        '''
        elements = self.__root.getElementsByTagName(elemName)
        if elements :
            return elements[0]

        return elements

    def __createTextNode(self,data):
        '''
        Creates a text node with utf8 data inside.
        The text is escaped to an fit the xml text Format.
        '''
        if data is None :
            return self.__doc.createTextNode(u'')
        else :
            escaped_data = saxutils.escape(self.__formatString(data), ENTITIES)
            return self.__doc.createTextNode(escaped_data)

    def __createAttribute(self,attrName,attrValue):
        '''
        Creates an attribute node with utf8 data inside.
        The text is escaped to an fit the xml text Format.
        '''
        attr = self.__doc.createAttribute(attrName)
        if attrValue is None :
            attr.nodeValue = u''
        else :
            attr.nodeValue = getUnicode(attrValue)
        return attr

    def __formatString(self, inpStr):
        return restoreDumpMarkedChars(getUnicode(inpStr))

    def string(self, header, data, sort=True):
        '''
        Adds string element to the xml.
        '''
        if isinstance(data, (list, tuple, set)):
            self.lister(header, data, sort)
            return

        messagesElem = self.__getRootChild(MESSAGES_ELEM_NAME)
        if (not(messagesElem)):
            messagesElem = self.__doc.createElement(MESSAGES_ELEM_NAME)
            self.__addToRoot(messagesElem)

        if data:
            data = self.__formatString(data)
        else :
            data = ""

        elem = self.__doc.createElement(MESSAGE_ELEM)
        elem.setAttributeNode(self.__createAttribute(TYPE_ATTR, header))
        elem.appendChild(self.__createTextNode(data))
        messagesElem.appendChild(elem)

    def lister(self, header, elements, sort=True):
        '''
        Adds information formatted as list element
        '''
        lstElem = self.__doc.createElement(LST_ELEM_NAME)
        lstElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, header))
        if elements:

            if sort:
                try:
                    elements = set(elements)
                    elements = list(elements)
                    elements.sort(key=lambda x: x.lower())
                except:
                    pass

            for element in elements:
                memberElem = self.__doc.createElement(MEMBER_ELEM)
                lstElem.appendChild(memberElem)
                if isinstance(element, basestring):
                    memberElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, "string"))
                    memberElem.appendChild(self.__createTextNode(element))
                elif isinstance(element, (list, tuple, set)):
                    memberElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, "list"))
                    for e in element :
                        memberElemStr = self.__doc.createElement(MEMBER_ELEM)
                        memberElemStr.setAttributeNode(self.__createAttribute(TYPE_ATTR, "string"))
                        memberElemStr.appendChild(self.__createTextNode(getUnicode(e)))
                        memberElem.appendChild(memberElemStr)
        listsElem = self.__getRootChild(LSTS_ELEM_NAME)
        if not(listsElem):
            listsElem = self.__doc.createElement(LSTS_ELEM_NAME)
            self.__addToRoot(listsElem)
        listsElem.appendChild(lstElem)

    def technic(self,technicType,data):
        '''
        Adds information about the technic used to extract data from the db
        '''
        technicElem = self.__doc.createElement(TECHNIC_ELEM_NAME)
        technicElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, technicType))
        textNode = self.__createTextNode(data)
        technicElem.appendChild(textNode)
        technicsElem = self.__getRootChild(TECHNICS_ELEM_NAME)
        if not(technicsElem):
            technicsElem = self.__doc.createElement(TECHNICS_ELEM_NAME)
            self.__addToRoot(technicsElem)
        technicsElem.appendChild(technicElem)

    def banner(self,data):
        '''
        Adds information about the database banner to the xml.
        The banner contains information about the type and the version of the database.
        '''
        bannerElem = self.__doc.createElement(BANNER_ELEM_NAME)
        bannerElem.appendChild(self.__createTextNode(data))
        self.__addToRoot(bannerElem)

    def currentUser(self,data):
        '''
        Adds information about the current database user to the xml
        '''
        currentUserElem = self.__doc.createElement(CURRENT_USER_ELEM_NAME)
        textNode = self.__createTextNode(data)
        currentUserElem.appendChild(textNode)
        self.__addToRoot(currentUserElem)

    def currentDb(self,data):
        '''
        Adds information about the current database is use to the xml
        '''
        currentDBElem = self.__doc.createElement(CURRENT_DB_ELEM_NAME)
        textNode = self.__createTextNode(data)
        currentDBElem.appendChild(textNode)
        self.__addToRoot(currentDBElem)

    def dba(self,isDBA):
        '''
        Adds information to the xml that indicates whether the user has DBA privileges
        '''
        isDBAElem = self.__doc.createElement(IS_DBA_ELEM_NAME)
        isDBAElem.setAttributeNode(self.__createAttribute(VALUE_ATTR, getUnicode(isDBA)))
        self.__addToRoot(isDBAElem)

    def users(self,users):
        '''
        Adds a list of the existing users to the xml
        '''
        usersElem = self.__doc.createElement(USERS_ELEM_NAME)
        if isinstance(users, basestring):
            users = [users]
        if users:
            for user in users:
                userElem = self.__doc.createElement(DB_USER_ELEM_NAME)
                usersElem.appendChild(userElem)
                userElem.appendChild(self.__createTextNode(user))
        self.__addToRoot(usersElem)

    def dbs(self, dbs):
        '''
        Adds a list of the existing databases to the xml
        '''
        dbsElem = self.__doc.createElement(DBS_ELEM_NAME)
        if dbs:
            for db in dbs:
                dbElem = self.__doc.createElement(DB_NAME_ELEM_NAME)
                dbsElem.appendChild(dbElem)
                dbElem.appendChild(self.__createTextNode(db))
        self.__addToRoot(dbsElem)

    def userSettings(self, header, userSettings, subHeader):
        '''
        Adds information about the user's settings to the xml.
        The information can be user's passwords, privileges and etc..
        '''
        self.__areAdmins = set()
        userSettingsElem = self.__getRootChild(USER_SETTINGS_ELEM_NAME)
        if (not(userSettingsElem)):
            userSettingsElem = self.__doc.createElement(USER_SETTINGS_ELEM_NAME)
            self.__addToRoot(userSettingsElem)

        userSettingElem = self.__doc.createElement(USER_SETTING_ELEM_NAME)
        userSettingElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, header))

        if isinstance(userSettings, (tuple, list, set)):
            self.__areAdmins = userSettings[1]
            userSettings = userSettings[0]

        users = userSettings.keys()
        users.sort(key=lambda x: x.lower())

        for user in users:
            userElem = self.__doc.createElement(USER_ELEM_NAME)
            userSettingElem.appendChild(userElem)
            if user in self.__areAdmins:
                userElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, ADMIN_USER))
            else:
                userElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, REGULAR_USER))

            settings = userSettings[user]

            settings.sort()

            for setting in settings:
                settingsElem = self.__doc.createElement(SETTINGS_ELEM_NAME)
                settingsElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, subHeader))
                settingTextNode = self.__createTextNode(setting)
                settingsElem.appendChild(settingTextNode)
                userElem.appendChild(settingsElem)
        userSettingsElem.appendChild(userSettingElem)

    def dbTables(self, dbTables):
        '''
        Adds information of the existing db tables to the xml
        '''
        if not isinstance(dbTables, dict):
            self.string(TABLES_ELEM_NAME, dbTables)
            return

        dbTablesElem = self.__doc.createElement(DB_TABLES_ELEM_NAME)

        for db, tables in dbTables.items():
            tables.sort(key=lambda x: x.lower())
            dbElem = self.__doc.createElement(DATABASE_ELEM_NAME)
            dbElem.setAttributeNode(self.__createAttribute(NAME_ATTR,db))
            dbTablesElem.appendChild(dbElem)
            for table in tables:
                tableElem = self.__doc.createElement(DB_TABLE_ELEM_NAME)
                tableElem.appendChild(self.__createTextNode(table))
                dbElem.appendChild(tableElem)
        self.__addToRoot(dbTablesElem)

    def dbTableColumns(self, tableColumns):
        '''
        Adds information about the columns of the existing tables to the xml
        '''

        columnsElem = self.__getRootChild(COLUMNS_ELEM_NAME)
        if not(columnsElem):
            columnsElem = self.__doc.createElement(COLUMNS_ELEM_NAME)

        for db, tables in tableColumns.items():
            if not db:
                db = DEFAULT_DB
            dbElem = self.__doc.createElement(DATABASE_COLUMNS_ELEM)
            dbElem.setAttributeNode(self.__createAttribute(NAME_ATTR, db))
            columnsElem.appendChild(dbElem)

            for table, columns in tables.items():
                tableElem = self.__doc.createElement(TABLE_ELEM_NAME)
                tableElem.setAttributeNode(self.__createAttribute(NAME_ATTR, table))

                colList = columns.keys()
                colList.sort(key=lambda x: x.lower())

                for column in colList:
                    colType = columns[column]
                    colElem = self.__doc.createElement(COLUMN_ELEM_NAME)
                    if colType is not None:
                        colElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, colType))
                    else :
                        colElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, UNKNOWN_COLUMN_TYPE))
                    colElem.appendChild(self.__createTextNode(column))
                    tableElem.appendChild(colElem)

        self.__addToRoot(columnsElem)

    def dbTableValues(self, tableValues):
        '''
        Adds the values of specific table to the xml.
        The values are organized according to the relevant row and column.
        '''
        tableElem = self.__doc.createElement(DB_TABLE_VALUES_ELEM_NAME)
        if (tableValues is not None):
            db = tableValues["__infos__"]["db"]
            if not db:
                db = "All"
            table = tableValues["__infos__"]["table"]

            count     = int(tableValues["__infos__"]["count"])
            columns = tableValues.keys()
            columns.sort(key=lambda x: x.lower())

            tableElem.setAttributeNode(self.__createAttribute(DB_ATTR, db))
            tableElem.setAttributeNode(self.__createAttribute(NAME_ATTR, table))

            for i in range(count):
                rowElem = self.__doc.createElement(ROW_ELEM_NAME)
                tableElem.appendChild(rowElem)
                for column in columns:
                    if column != "__infos__":
                        info = tableValues[column]
                        value = info["values"][i]

                        if re.search("^[\ *]*$", value):
                            value = "NULL"

                        cellElem = self.__doc.createElement(CELL_ELEM_NAME)
                        cellElem.setAttributeNode(self.__createAttribute(COLUMN_ATTR, column))
                        cellElem.appendChild(self.__createTextNode(value))
                        rowElem.appendChild(cellElem)

        dbValuesElem = self.__getRootChild(DB_VALUES_ELEM)
        if (not(dbValuesElem)):
            dbValuesElem = self.__doc.createElement(DB_VALUES_ELEM)
            self.__addToRoot(dbValuesElem)

        dbValuesElem.appendChild(tableElem)

        logger.info("Table '%s.%s' dumped to XML file" % (db, table))

    def dbColumns(self, dbColumns, colConsider, dbs):
        '''
        Adds information about the columns
        '''
        for column in dbColumns.keys():
            printDbs = {}
            for db, tblData in dbs.items():
                for tbl, colData in tblData.items():
                    for col, dataType in colData.items():
                        if column in col:
                            if db in printDbs:
                                if tbl in printDbs[db]:
                                    printDbs[db][tbl][col] = dataType
                                else:
                                    printDbs[db][tbl] = { col: dataType }
                            else:
                                printDbs[db] = {}
                                printDbs[db][tbl] = { col: dataType }

                            continue

        self.dbTableColumns(printDbs)

    def query(self,query,queryRes):
        '''
        Adds details of an executed query to the xml.
        The query details are the query itself and it's results.
        '''
        queryElem = self.__doc.createElement(QUERY_ELEM_NAME)
        queryElem.setAttributeNode(self.__createAttribute(VALUE_ATTR, query))
        queryElem.appendChild(self.__createTextNode(queryRes))
        queriesElem = self.__getRootChild(QUERIES_ELEM_NAME)
        if (not(queriesElem)):
            queriesElem = self.__doc.createElement(QUERIES_ELEM_NAME)
            self.__addToRoot(queriesElem)
        queriesElem.appendChild(queryElem)

    def registerValue(self,registerData):
        '''
        Adds information about an extracted registry key to the xml
        '''
        registerElem = self.__doc.createElement(REGISTER_DATA_ELEM_NAME)
        registerElem.appendChild(self.__createTextNode(registerData))
        registriesElem = self.__getRootChild(REGISTERY_ENTRIES_ELEM_NAME)
        if (not(registriesElem)):
            registriesElem = self.__doc.createElement(REGISTERY_ENTRIES_ELEM_NAME)
            self.__addToRoot(registriesElem)
        registriesElem.appendChild(registerElem)

    def rFile(self, filePath, data):
        '''
        Adds an extracted file's content to the xml
        '''
        fileContentElem = self.__doc.createElement(FILE_CONTENT_ELEM_NAME)
        fileContentElem.setAttributeNode(self.__createAttribute(NAME_ATTR, filePath))
        fileContentElem.appendChild(self.__createTextNode(data))
        self.__addToRoot(fileContentElem)

    def setOutputFile(self):
        '''
        Initiates the xml file from the configuration.
        '''
        if (conf.xmlFile) :
            try :
                self.__outputFile = conf.xmlFile
                self.__root = None

                if os.path.exists(self.__outputFile):
                    try:
                        self.__doc = xml.dom.minidom.parse(self.__outputFile)
                        self.__root = self.__doc.childNodes[0]
                    except ExpatError:
                        self.__doc = Document()

                self.__outputFP = codecs.open(self.__outputFile, "w+", UNICODE_ENCODING)

                if self.__root is None:
                    self.__root = self.__doc.createElementNS(NAME_SPACE_ATTR, RESULTS_ELEM_NAME)
                    self.__root.setAttributeNode(self.__createAttribute(XMLNS_ATTR,NAME_SPACE_ATTR))
                    self.__root.setAttributeNode(self.__createAttribute(SCHEME_NAME_ATTR,SCHEME_NAME))
                    self.__doc.appendChild(self.__root)
            except IOError:
                raise sqlmapFilePathException("Wrong filename provided for saving the xml file: %s" % conf.xmlFile)

    def getOutputFile(self):
        return self.__outputFile

    def finish(self, resultStatus, resultMsg=""):
        '''
        Finishes the dumper operation:
        1. Adds the session status to the xml
        2. Writes the xml to the file
        3. Closes the xml file
        '''
        if ((self.__outputFP is not None) and not(self.__outputFP.closed)):
            statusElem = self.__doc.createElement(STATUS_ELEM_NAME)
            statusElem.setAttributeNode(self.__createAttribute(SUCESS_ATTR,getUnicode(resultStatus)))

            if not resultStatus:
                errorElem = self.__doc.createElement(ERROR_ELEM_NAME)

                if isinstance(resultMsg, Exception):
                    errorElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, type(resultMsg).__name__))
                else:
                    errorElem.setAttributeNode(self.__createAttribute(TYPE_ATTR, UNHANDLED_PROBLEM_TYPE))

                errorElem.appendChild(self.__createTextNode(getUnicode(resultMsg)))
                statusElem.appendChild(errorElem)

            self.__addToRoot(statusElem)
            self.__write(prettyprint.formatXML(self.__doc, encoding=UNICODE_ENCODING))
            self.__outputFP.close()

def closeDumper(status, msg=""):
    """
    Closes the dumper of the session
    """

    if hasattr(conf, "dumper") and hasattr(conf.dumper, "finish"):
        conf.dumper.finish(status, msg)

dumper = XMLDump()
