#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import hashlib
import sqlite3

from lib.core.settings import UNICODE_ENCODING

class HashDB:
    def __init__(self, filepath):
        self.connection = sqlite3.connect(filepath)
        self.cursor = self.connection.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS storage (id INTEGER PRIMARY KEY, value TEXT)")

    def __del__(self):
        self.close()

    def close(self):
        try:
            self.endTransaction()
            self.connection.close()
        except:
            pass

    def hashKey(self, key):
        key = key.encode(UNICODE_ENCODING) if isinstance(key, unicode) else repr(key)
        retVal = int(hashlib.md5(key).hexdigest()[:8], 16)
        return retVal

    def beginTransaction(self):
        """
        Great speed improvement can be gained by using explicit transactions around multiple inserts.
        Reference: http://stackoverflow.com/questions/4719836/python-and-sqlite3-adding-thousands-of-rows
        """
        self.cursor.execute('BEGIN TRANSACTION')

    def endTransaction(self):
        try:
            self.cursor.execute('END TRANSACTION')
        except sqlite3.OperationalError:
            pass

    def retrieve(self, key):
        retVal = None
        if key:
            hash_ = self.hashKey(key)
            for row in self.cursor.execute("SELECT value FROM storage WHERE id=?", (hash_,)):
                retVal = row[0]
        return retVal

    def write(self, key, value):
        if key:
            hash_ = self.hashKey(key)
            try:
                self.cursor.execute("INSERT INTO storage VALUES (?, ?)", (hash_, value,))
            except sqlite3.IntegrityError:
                self.cursor.execute("UPDATE storage SET value=? WHERE id=?", (value, hash_,))
