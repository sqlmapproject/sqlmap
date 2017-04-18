#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import hashlib
import os
import sqlite3
import threading
import time

from lib.core.common import getSafeExString
from lib.core.common import getUnicode
from lib.core.common import serializeObject
from lib.core.common import singleTimeWarnMessage
from lib.core.common import unserializeObject
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from lib.core.settings import HASHDB_END_TRANSACTION_RETRIES
from lib.core.settings import HASHDB_FLUSH_RETRIES
from lib.core.settings import HASHDB_FLUSH_THRESHOLD
from lib.core.settings import HASHDB_RETRIEVE_RETRIES
from lib.core.settings import UNICODE_ENCODING
from lib.core.threads import getCurrentThreadData
from lib.core.threads import getCurrentThreadName

class HashDB(object):
    def __init__(self, filepath):
        self.filepath = filepath
        self._write_cache = {}
        self._cache_lock = threading.Lock()

    def _get_cursor(self):
        threadData = getCurrentThreadData()

        if threadData.hashDBCursor is None:
            try:
                connection = sqlite3.connect(self.filepath, timeout=3, isolation_level=None)
                threadData.hashDBCursor = connection.cursor()
                threadData.hashDBCursor.execute("CREATE TABLE IF NOT EXISTS storage (id INTEGER PRIMARY KEY, value TEXT)")
                connection.commit()
            except Exception, ex:
                errMsg = "error occurred while opening a session "
                errMsg += "file '%s' ('%s')" % (self.filepath, getSafeExString(ex))
                raise SqlmapConnectionException(errMsg)

        return threadData.hashDBCursor

    def _set_cursor(self, cursor):
        threadData = getCurrentThreadData()
        threadData.hashDBCursor = cursor

    cursor = property(_get_cursor, _set_cursor)

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
        retVal = int(hashlib.md5(key).hexdigest(), 16) & 0x7fffffffffffffff  # Reference: http://stackoverflow.com/a/4448400
        return retVal

    def retrieve(self, key, unserialize=False):
        retVal = None

        if key and (self._write_cache or os.path.isfile(self.filepath)):
            hash_ = HashDB.hashKey(key)
            retVal = self._write_cache.get(hash_)
            if not retVal:
                for _ in xrange(HASHDB_RETRIEVE_RETRIES):
                    try:
                        for row in self.cursor.execute("SELECT value FROM storage WHERE id=?", (hash_,)):
                            retVal = row[0]
                    except sqlite3.OperationalError, ex:
                        if any(_ in getSafeExString(ex) for _ in ("locked", "no such table")):
                            warnMsg = "problem occurred while accessing session file '%s' ('%s')" % (self.filepath, getSafeExString(ex))
                            singleTimeWarnMessage(warnMsg)
                        elif "Could not decode" in getSafeExString(ex):
                            break
                        else:
                            raise
                    except sqlite3.DatabaseError, ex:
                        errMsg = "error occurred while accessing session file '%s' ('%s'). " % (self.filepath, getSafeExString(ex))
                        errMsg += "If the problem persists please rerun with `--flush-session`"
                        raise SqlmapConnectionException, errMsg
                    else:
                        break

                    time.sleep(1)

        if retVal and unserialize:
            try:
                retVal = unserializeObject(retVal)
            except:
                retVal = None
                warnMsg = "error occurred while unserializing value for session key '%s'. " % key
                warnMsg += "If the problem persists please rerun with `--flush-session`"
                logger.warn(warnMsg)

        return retVal

    def write(self, key, value, serialize=False):
        if key:
            hash_ = HashDB.hashKey(key)
            self._cache_lock.acquire()
            self._write_cache[hash_] = getUnicode(value) if not serialize else serializeObject(value)
            self._cache_lock.release()

        if getCurrentThreadName() in ('0', 'MainThread'):
            self.flush()

    def flush(self, forced=False):
        if not self._write_cache:
            return

        if not forced and len(self._write_cache) < HASHDB_FLUSH_THRESHOLD:
            return

        self._cache_lock.acquire()
        _ = self._write_cache
        self._write_cache = {}
        self._cache_lock.release()

        try:
            self.beginTransaction()
            for hash_, value in _.items():
                retries = 0
                while True:
                    try:
                        try:
                            self.cursor.execute("INSERT INTO storage VALUES (?, ?)", (hash_, value,))
                        except sqlite3.IntegrityError:
                            self.cursor.execute("UPDATE storage SET value=? WHERE id=?", (value, hash_,))
                    except sqlite3.DatabaseError, ex:
                        if not os.path.exists(self.filepath):
                            debugMsg = "session file '%s' does not exist" % self.filepath
                            logger.debug(debugMsg)
                            break

                        if retries == 0:
                            warnMsg = "there has been a problem while writing to "
                            warnMsg += "the session file ('%s')" % getSafeExString(ex)
                            logger.warn(warnMsg)

                        if retries >= HASHDB_FLUSH_RETRIES:
                            return
                        else:
                            retries += 1
                            time.sleep(1)
                    else:
                        break
        finally:
            self.endTransaction()

    def beginTransaction(self):
        threadData = getCurrentThreadData()
        if not threadData.inTransaction:
            try:
                self.cursor.execute("BEGIN TRANSACTION")
            except:
                # Reference: http://stackoverflow.com/a/25245731
                self.cursor.close()
                threadData.hashDBCursor = None
                self.cursor.execute("BEGIN TRANSACTION")
            finally:
                threadData.inTransaction = True

    def endTransaction(self):
        threadData = getCurrentThreadData()
        if threadData.inTransaction:
            retries = 0
            while retries < HASHDB_END_TRANSACTION_RETRIES:
                try:
                    self.cursor.execute("END TRANSACTION")
                    threadData.inTransaction = False
                except sqlite3.OperationalError:
                    pass
                else:
                    return

                retries += 1
                time.sleep(1)

            try:
                self.cursor.execute("ROLLBACK TRANSACTION")
            except sqlite3.OperationalError:
                self.cursor.close()
                self.cursor = None
            finally:
                threadData.inTransaction = False
