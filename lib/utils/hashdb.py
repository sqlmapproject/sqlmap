#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import hashlib
import sqlite3

from lib.core.data import conf
from lib.core.settings import UNICODE_ENCODING
from lib.core.threads import getCurrentThreadData

class HashDB(object):
    def __init__(self, filepath):
        self.filepath = filepath

    def _get_cursor(self):
        threadData = getCurrentThreadData()

        if threadData.hashDBCursor is None:
            connection = sqlite3.connect(self.filepath, timeout=3, isolation_level=None)
            threadData.hashDBCursor = connection.cursor()
            threadData.hashDBCursor.execute("CREATE TABLE IF NOT EXISTS storage (id INTEGER PRIMARY KEY, value TEXT)")

        return threadData.hashDBCursor

    cursor = property(_get_cursor)

    def close(self):
        threadData = getCurrentThreadData()
        try:
            if threadData.hashDBCursor:
                threadData.hashDBCursor.close()
                threadData.hashDBCursor.connection.close()
                threadData.hashDBCursor = None
        except:
            pass

    @staticmethod
    def hashKey(key):
        key = key.encode(UNICODE_ENCODING) if isinstance(key, unicode) else repr(key)
        retVal = int(hashlib.md5(key).hexdigest()[:8], 16)
        return retVal

    def retrieve(self, key):
        retVal = None
        if key:
            hash_ = HashDB.hashKey(key)
            while True:
                try:
                    for row in self.cursor.execute("SELECT value FROM storage WHERE id=?", (hash_,)):
                        retVal = row[0]
                except sqlite3.OperationalError, ex:
                    if not 'locked' in ex.message:
                        raise
                else:
                    break
        return retVal

    def write(self, key, value):
        if key:
            hash_ = HashDB.hashKey(key)
            while True:
                try:
                    try:
                        self.cursor.execute("INSERT INTO storage VALUES (?, ?)", (hash_, value,))
                    except sqlite3.IntegrityError:
                        self.cursor.execute("UPDATE storage SET value=? WHERE id=?", (value, hash_,))
                except sqlite3.OperationalError, ex:
                    if not 'locked' in ex.message:
                        raise
                else:
                    break

    def beginTransaction(self):
        self.cursor.execute('BEGIN TRANSACTION')

    def endTransaction(self):
        self.cursor.execute('END TRANSACTION')
