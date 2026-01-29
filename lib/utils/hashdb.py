#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import hashlib
import os
import sqlite3
import struct
import threading
import time

from lib.core.common import getSafeExString
from lib.core.common import serializeObject
from lib.core.common import singleTimeWarnMessage
from lib.core.common import unserializeObject
from lib.core.compat import xrange
from lib.core.convert import getBytes
from lib.core.convert import getUnicode
from lib.core.data import logger
from lib.core.datatype import LRUDict
from lib.core.exception import SqlmapConnectionException
from lib.core.settings import HASHDB_END_TRANSACTION_RETRIES
from lib.core.settings import HASHDB_FLUSH_RETRIES
from lib.core.settings import HASHDB_FLUSH_THRESHOLD_ITEMS
from lib.core.settings import HASHDB_FLUSH_THRESHOLD_TIME
from lib.core.settings import HASHDB_RETRIEVE_RETRIES
from lib.core.settings import IS_PYPY
from lib.core.threads import getCurrentThreadData
from thirdparty import six

class HashDB(object):
    def __init__(self, filepath):
        self.filepath = filepath
        self._write_cache = {}
        self._read_cache = LRUDict(capacity=100)
        self._cache_lock = threading.Lock()
        self._connections = []
        self._last_flush_time = time.time()

    def _get_cursor(self):
        threadData = getCurrentThreadData()

        if threadData.hashDBCursor is None:
            try:
                connection = sqlite3.connect(self.filepath, timeout=10, isolation_level=None, check_same_thread=False)
                if not IS_PYPY:
                    connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=NORMAL")
                connection.execute("PRAGMA busy_timeout=10000")
                self._connections.append(connection)
                threadData.hashDBCursor = connection.cursor()
                threadData.hashDBCursor.execute("CREATE TABLE IF NOT EXISTS storage (id INTEGER PRIMARY KEY, value TEXT)")
                connection.commit()
            except Exception as ex:
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
                if self._write_cache:
                    self.flush()

                threadData.hashDBCursor.close()
                threadData.hashDBCursor.connection.close()
                threadData.hashDBCursor = None
        except:
            pass

    def closeAll(self):
        if self._write_cache:
            self.flush()

        for connection in self._connections:
            try:
                connection.close()
            except:
                pass

    @staticmethod
    def hashKey(key):
        key = getBytes(key if isinstance(key, six.text_type) else repr(key), errors="xmlcharrefreplace")
        retVal = struct.unpack("<Q", hashlib.md5(key).digest()[:8])[0] & 0x7fffffffffffffff
        return retVal

    def retrieve(self, key, unserialize=False):
        retVal = None

        if key and (self._write_cache or self._connections or os.path.isfile(self.filepath)):
            hash_ = HashDB.hashKey(key)
            retVal = self._write_cache.get(hash_)

            if retVal is None:
                retVal = self._read_cache.get(hash_)

            if not retVal:
                for _ in xrange(HASHDB_RETRIEVE_RETRIES):
                    try:
                        for row in self.cursor.execute("SELECT value FROM storage WHERE id=?", (hash_,)):
                            retVal = row[0]
                    except (sqlite3.OperationalError, sqlite3.DatabaseError) as ex:
                        if any(_ in getSafeExString(ex) for _ in ("locked", "no such table")):
                            warnMsg = "problem occurred while accessing session file '%s' ('%s')" % (self.filepath, getSafeExString(ex))
                            singleTimeWarnMessage(warnMsg)
                        elif "Could not decode" in getSafeExString(ex):
                            break
                        else:
                            errMsg = "error occurred while accessing session file '%s' ('%s'). " % (self.filepath, getSafeExString(ex))
                            errMsg += "If the problem persists please rerun with '--flush-session'"
                            raise SqlmapConnectionException(errMsg)
                    else:
                        break

                    time.sleep(1)

                if retVal is not None:
                    self._read_cache[hash_] = retVal

        if retVal and unserialize:
            try:
                retVal = unserializeObject(retVal)
            except:
                retVal = None
                warnMsg = "error occurred while unserializing value for session key '%s'. " % key
                warnMsg += "If the problem persists please rerun with '--flush-session'"
                logger.warning(warnMsg)

        return retVal

    def write(self, key, value, serialize=False):
        if key:
            hash_ = HashDB.hashKey(key)
            with self._cache_lock:
                self._write_cache[hash_] = self._read_cache[hash_] = getUnicode(value) if not serialize else serializeObject(value)
                cache_size = len(self._write_cache)
                time_since_flush = time.time() - self._last_flush_time

            if cache_size >= HASHDB_FLUSH_THRESHOLD_ITEMS or time_since_flush >= HASHDB_FLUSH_THRESHOLD_TIME:
                self.flush()

    def flush(self):
        with self._cache_lock:
            if not self._write_cache:
                return

            flush_cache = self._write_cache
            self._write_cache = {}
            self._last_flush_time = time.time()

        try:
            self.beginTransaction()
            for hash_, value in flush_cache.items():
                retries = 0
                while True:
                    try:
                        try:
                            self.cursor.execute("INSERT INTO storage VALUES (?, ?)", (hash_, value,))
                        except sqlite3.IntegrityError:
                            self.cursor.execute("UPDATE storage SET value=? WHERE id=?", (value, hash_,))
                    except (UnicodeError, OverflowError):  # e.g. surrogates not allowed (Issue #3851)
                        break
                    except sqlite3.DatabaseError as ex:
                        if not os.path.exists(self.filepath):
                            debugMsg = "session file '%s' does not exist" % self.filepath
                            logger.debug(debugMsg)
                            break

                        # NOTE: skipping the retries == 0 for graceful resolution of multi-threaded runs
                        if retries == 1:
                            warnMsg = "there has been a problem while writing to "
                            warnMsg += "the session file ('%s')" % getSafeExString(ex)
                            logger.warning(warnMsg)

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
                try:
                    # Reference: http://stackoverflow.com/a/25245731
                    self.cursor.close()
                except sqlite3.ProgrammingError:
                    pass
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
                except sqlite3.ProgrammingError:
                    self.cursor = None
                    threadData.inTransaction = False
                    return
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
