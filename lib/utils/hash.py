#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

try:
    from crypt import crypt
except ImportError, _:
    from extra.fcrypt.fcrypt import crypt

_multiprocessing = None
try:
    import multiprocessing

    # problems on FreeBSD (Reference: http://www.eggheadcafe.com/microsoft/Python/35880259/multiprocessing-on-freebsd.aspx)
    _ = multiprocessing.Queue()
except (ImportError, OSError):
    pass
else:
    _multiprocessing = multiprocessing

import os
import re
import time

from hashlib import md5
from hashlib import sha1
from Queue import Queue
from zipfile import ZipFile

from extra.pydes.pyDes import des
from extra.pydes.pyDes import CBC
from lib.core.common import Backend
from lib.core.common import checkFile
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import getCompiledRegex
from lib.core.common import getFileItems
from lib.core.common import getPublicTypeMembers
from lib.core.common import normalizeUnicode
from lib.core.common import paths
from lib.core.common import readInput
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import Wordlist
from lib.core.convert import hexdecode
from lib.core.convert import hexencode
from lib.core.convert import utf8encode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import HASH
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapUserQuitException
from lib.core.settings import COMMON_PASSWORD_SUFFIXES
from lib.core.settings import COMMON_USER_COLUMNS
from lib.core.settings import DUMMY_USER_PREFIX
from lib.core.settings import HASH_MOD_ITEM_DISPLAY
from lib.core.settings import HASH_RECOGNITION_QUIT_THRESHOLD
from lib.core.settings import IS_WIN
from lib.core.settings import ITOA64
from lib.core.settings import PYVERSION
from lib.core.settings import ML
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import ROTATING_CHARS

def mysql_passwd(password, uppercase=True):
    """
    Reference(s):
        http://csl.sublevel3.org/mysql-password-function/

    >>> mysql_passwd(password='testpass', uppercase=True)
    '*00E247AC5F9AF26AE0194B41E1E769DEE1429A29'
    """

    retVal = "*%s" % sha1(sha1(password).digest()).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def mysql_old_passwd(password, uppercase=True): # prior to version '4.1'
    """
    Reference(s):
        http://www.sfr-fresh.com/unix/privat/tpop3d-1.5.5.tar.gz:a/tpop3d-1.5.5/password.c
        http://voidnetwork.org/5ynL0rd/darkc0de/python_script/darkMySQLi.html

    >>> mysql_old_passwd(password='testpass', uppercase=True)
    '7DCDA0D57290B453'
    """

    a, b, c = 1345345333, 7, 0x12345671

    for d in password:
        if d == ' ' or d == '\t':
            continue

        e = ord(d)
        a ^= (((a & 63) + b) * e) + (a << 8)
        c += (c << 8) ^ a
        b += e

    retVal = "%08lx%08lx" % (a & ((1 << 31) - 1), c & ((1 << 31) - 1))

    return retVal.upper() if uppercase else retVal.lower()

def postgres_passwd(password, username, uppercase=False):
    """
    Reference(s):
        http://pentestmonkey.net/blog/cracking-postgres-hashes/

    >>> postgres_passwd(password='testpass', username='testuser', uppercase=False)
    'md599e5ea7a6f7c3269995cba3927fd0093'
    """

    retVal = "md5%s" % md5(password + username).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def mssql_passwd(password, salt, uppercase=False):
    """
    Reference(s):
        http://www.leidecker.info/projects/phrasendrescher/mssql.c
        https://www.evilfingers.com/tools/GSAuditor.php

    >>> mssql_passwd(password='testpass', salt='4086ceb6', uppercase=False)
    '0x01004086ceb60c90646a8ab9889fe3ed8e5c150b5460ece8425a'
    """

    binsalt = hexdecode(salt)
    unistr = "".join(map(lambda c: ("%s\0" if ord(c) < 256 else "%s") % utf8encode(c), password))

    retVal = "0100%s%s" % (salt, sha1(unistr + binsalt).hexdigest())

    return "0x%s" % (retVal.upper() if uppercase else retVal.lower())

def mssql_old_passwd(password, salt, uppercase=True): # prior to version '2005'
    """
    Reference(s):
        www.exploit-db.com/download_pdf/15537/
        http://www.leidecker.info/projects/phrasendrescher/mssql.c
        https://www.evilfingers.com/tools/GSAuditor.php

    >>> mssql_old_passwd(password='testpass', salt='4086ceb6', uppercase=True)
    '0x01004086CEB60C90646A8AB9889FE3ED8E5C150B5460ECE8425AC7BB7255C0C81D79AA5D0E93D4BB077FB9A51DA0'
    """

    binsalt = hexdecode(salt)
    unistr = "".join(map(lambda c: ("%s\0" if ord(c) < 256 else "%s") % utf8encode(c), password))

    retVal = "0100%s%s%s" % (salt, sha1(unistr + binsalt).hexdigest(), sha1(unistr.upper() + binsalt).hexdigest())

    return "0x%s" % (retVal.upper() if uppercase else retVal.lower())

def oracle_passwd(password, salt, uppercase=True):
    """
    Reference(s):
        https://www.evilfingers.com/tools/GSAuditor.php
        http://www.notesbit.com/index.php/scripts-oracle/oracle-11g-new-password-algorithm-is-revealed-by-seclistsorg/
        http://seclists.org/bugtraq/2007/Sep/304

    >>> oracle_passwd(password='SHAlala', salt='1B7B5F82B7235E9E182C', uppercase=True)
    'S:2BFCFDF5895014EE9BB2B9BA067B01E0389BB5711B7B5F82B7235E9E182C'
    """

    binsalt = hexdecode(salt)

    retVal="s:%s%s" % (sha1(utf8encode(password) + binsalt).hexdigest(), salt)

    return retVal.upper() if uppercase else retVal.lower()

def oracle_old_passwd(password, username, uppercase=True): # prior to version '11g'
    """
    Reference(s):
        http://www.notesbit.com/index.php/scripts-oracle/oracle-11g-new-password-algorithm-is-revealed-by-seclistsorg/

    >>> oracle_old_passwd(password='tiger', username='scott', uppercase=True)
    'F894844C34402B67'
    """

    IV, pad = "\0"*8, "\0"

    if isinstance(username, unicode):
        username = unicode.encode(username, UNICODE_ENCODING) #pyDes has issues with unicode strings

    unistr = "".join("\0%s" % c for c in (username + password).upper())

    cipher = des(hexdecode("0123456789ABCDEF"), CBC, IV, pad)
    encrypted = cipher.encrypt(unistr)
    cipher = des(encrypted[-8:], CBC, IV, pad)
    encrypted = cipher.encrypt(unistr)

    retVal = hexencode(encrypted[-8:])

    return retVal.upper() if uppercase else retVal.lower()

def md5_generic_passwd(password, uppercase=False):
    """
    >>> md5_generic_passwd(password='testpass', uppercase=False)
    '179ad45c6ce2cb97cf1029e212046e81'
    """

    retVal = md5(password).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def sha1_generic_passwd(password, uppercase=False):
    """
    >>> sha1_generic_passwd(password='testpass', uppercase=False)
    '206c80413b9a96c1312cc346b7d2517b84463edd'
    """

    retVal = sha1(password).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()


def crypt_generic_passwd(password, salt, uppercase=False):
    """
    Reference(s):
        http://docs.python.org/library/crypt.html
        http://helpful.knobs-dials.com/index.php/Hashing_notes
        http://php.net/manual/en/function.crypt.php
        http://carey.geek.nz/code/python-fcrypt/

    >>> crypt_generic_passwd(password='rasmuslerdorf', salt='rl', uppercase=False)
    'rl.3StKT.4T8M'
    """

    retVal = crypt(password, salt)

    return retVal.upper() if uppercase else retVal

def wordpress_passwd(password, salt, count, prefix, uppercase=False):
    """
    Reference(s):
        http://packetstormsecurity.org/files/74448/phpassbrute.py.txt
        http://scriptserver.mainframe8.com/wordpress_password_hasher.php

    >>> wordpress_passwd(password='testpass', salt='aD9ZLmkp', count=2048, prefix='$P$9aD9ZLmkp', uppercase=False)
    '$P$9aD9ZLmkpsN4A83G8MefaaP888gVKX0'
    """

    def _encode64(input_, count):
        output = ''
        i = 0

        while i < count:
            value = ord(input_[i])
            i += 1
            output = output + ITOA64[value & 0x3f]

            if i < count:
                value = value | (ord(input_[i]) << 8)

            output = output + ITOA64[(value>>6) & 0x3f]

            i += 1
            if i >= count:
                break

            if i < count:
                value = value | (ord(input_[i]) << 16)

            output = output + ITOA64[(value>>12) & 0x3f]

            i += 1
            if i >= count:
                break

            output = output + ITOA64[(value>>18) & 0x3f]

        return output

    cipher = md5(salt)
    cipher.update(password)
    hash_ = cipher.digest()

    for i in xrange(count):
        _ = md5(hash_)
        _.update(password)
        hash_ = _.digest()

    retVal = prefix + _encode64(hash_, 16)

    return retVal.upper() if uppercase else retVal

__functions__ = {
                    HASH.MYSQL: mysql_passwd, 
                    HASH.MYSQL_OLD: mysql_old_passwd,
                    HASH.POSTGRES: postgres_passwd, 
                    HASH.MSSQL: mssql_passwd, 
                    HASH.MSSQL_OLD: mssql_old_passwd, 
                    HASH.ORACLE: oracle_passwd,
                    HASH.ORACLE_OLD: oracle_old_passwd, 
                    HASH.MD5_GENERIC: md5_generic_passwd, 
                    HASH.SHA1_GENERIC: sha1_generic_passwd,
                    HASH.CRYPT_GENERIC: crypt_generic_passwd,
                    HASH.WORDPRESS: wordpress_passwd
                }

def attackCachedUsersPasswords():
    if kb.data.cachedUsersPasswords:
        results = dictionaryAttack(kb.data.cachedUsersPasswords)

        for (_, hash_, password) in results:
            for user in kb.data.cachedUsersPasswords.keys():
                for i in xrange(len(kb.data.cachedUsersPasswords[user])):
                    if kb.data.cachedUsersPasswords[user][i] and hash_.lower() in kb.data.cachedUsersPasswords[user][i].lower()\
                    and 'clear-text password' not in kb.data.cachedUsersPasswords[user][i].lower():
                        kb.data.cachedUsersPasswords[user][i] += "%s    clear-text password: %s" % ('\n' if kb.data.cachedUsersPasswords[user][i][-1] != '\n' else '', password)

def attackDumpedTable():
    if kb.data.dumpedTable:
        infoMsg = "analyzing table dump for possible password hashes"
        logger.info(infoMsg)

        table = kb.data.dumpedTable
        columns = table.keys()
        count = table["__infos__"]["count"]

        found = False
        colUser = ''
        colPasswords = set()
        attack_dict = {}

        for column in columns:
            if column and column.lower() in COMMON_USER_COLUMNS:
                colUser = column
                break

        for i in xrange(count):
            if not found and i > HASH_RECOGNITION_QUIT_THRESHOLD:
                break

            for column in columns:
                if column == colUser or column == '__infos__':
                    continue

                if len(table[column]['values']) <= i:
                    continue

                value = table[column]['values'][i]

                if hashRecognition(value):
                    found = True

                    if colUser and i < len(table[colUser]['values']):
                        if table[colUser]['values'][i] not in attack_dict:
                            attack_dict[table[colUser]['values'][i]] = []

                        attack_dict[table[colUser]['values'][i]].append(value)
                    else:
                        attack_dict['%s%d' % (DUMMY_USER_PREFIX, i)] = [value]

                    colPasswords.add(column)

        if attack_dict:
            message = "recognized possible password hashes in column%s " % ("s" if len(colPasswords) > 1 else "")
            message += "'%s'. Do you want to " % ", ".join(col for col in colPasswords)
            message += "crack them via a dictionary-based attack? [Y/n/q]"
            test = readInput(message, default="Y")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException

            results = dictionaryAttack(attack_dict)
            lut = dict()

            for (_, hash_, password) in results:
                if hash_:
                    lut[hash_.lower()] = password

            infoMsg = "postprocessing table dump"
            logger.info(infoMsg)

            for i in xrange(count):
                for column in columns:
                    if not (column == colUser or column == '__infos__' or len(table[column]['values']) <= i):
                        value = table[column]['values'][i]

                        if value and value.lower() in lut:
                            table[column]['values'][i] += " (%s)" % lut[value.lower()]
                            table[column]['length'] = max(table[column]['length'], len(table[column]['values'][i]))

def hashRecognition(value):
    retVal = None

    isOracle, isMySQL = Backend.isDbms(DBMS.ORACLE), Backend.isDbms(DBMS.MYSQL)

    if isinstance(value, basestring):
        for name, regex in getPublicTypeMembers(HASH):
            # Hashes for Oracle and old MySQL look the same hence these checks
            if isOracle and regex == HASH.MYSQL_OLD:
                continue
            elif isMySQL and regex == HASH.ORACLE_OLD:
                continue
            elif regex == HASH.CRYPT_GENERIC:
                if any((value.lower() == value, value.upper() == value)):
                    continue
            elif getCompiledRegex(regex).match(value):
                retVal = regex
                break

    return retVal

def __bruteProcessVariantA(attack_info, hash_regex, wordlist, suffix, retVal, proc_id, proc_count):
    count = 0
    rotator = 0
    hashes = set([item[0][1] for item in attack_info])

    try:
        for word in wordlist:
            if not attack_info:
                break

            if not isinstance(word, basestring):
                continue

            if suffix:
                word = word + suffix

            try:
                current = __functions__[hash_regex](password = word, uppercase = False)

                count += 1

                if current in hashes:
                    for item in attack_info[:]:
                        ((user, hash_), _) = item

                        if hash_ == current:
                            retVal.put((user, hash_, word))

                            clearConsoleLine()

                            infoMsg = "\r[%s] [INFO] cracked password '%s'" % (time.strftime("%X"), word)

                            if user and not user.startswith(DUMMY_USER_PREFIX):
                                infoMsg += " for user '%s'\n" % user
                            else:
                                infoMsg += " for hash '%s'\n" % hash_

                            dataToStdout(infoMsg, True)

                            attack_info.remove(item)

                elif (proc_id == 0 or getattr(proc_count, 'value', 0) == 1) and count % HASH_MOD_ITEM_DISPLAY == 0 or hash_regex == HASH.ORACLE_OLD or hash_regex == HASH.CRYPT_GENERIC and IS_WIN:
                    rotator += 1
                    if rotator >= len(ROTATING_CHARS):
                        rotator = 0
                    status = 'current status: %s... %s' % (word.ljust(5)[:5], ROTATING_CHARS[rotator])
                    dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status))

            except KeyboardInterrupt:
                raise

            except (UnicodeEncodeError, UnicodeDecodeError):
                pass # ignore possible encoding problems caused by some words in custom dictionaries

            except Exception, ex:
                print ex
                warnMsg = "there was a problem while hashing entry: %s. " % repr(word)
                warnMsg += "Please report by e-mail to %s" % ML
                logger.critical(warnMsg)

    except KeyboardInterrupt:
        pass

    finally:
        if hasattr(proc_count, 'value'):
            proc_count.value -= 1

def __bruteProcessVariantB(user, hash_, kwargs, hash_regex, wordlist, suffix, retVal, found, proc_id, proc_count):
    count = 0
    rotator = 0

    try:
        for word in wordlist:
            if found.value:
                break

            current = __functions__[hash_regex](password = word, uppercase = False, **kwargs)
            count += 1

            if not isinstance(word, basestring):
                continue

            if suffix:
                word = word + suffix

            try:
                if hash_ == current:
                    if hash_regex == HASH.ORACLE_OLD: #only for cosmetic purposes
                        word = word.upper()

                    retVal.put((user, hash_, word))

                    clearConsoleLine()

                    infoMsg = "\r[%s] [INFO] cracked password '%s'" % (time.strftime("%X"), word)

                    if user and not user.startswith(DUMMY_USER_PREFIX):
                        infoMsg += " for user '%s'\n" % user
                    else:
                        infoMsg += " for hash '%s'\n" % hash_

                    dataToStdout(infoMsg, True)

                    found.value = True

                elif (proc_id == 0 or getattr(proc_count, 'value', 0) == 1) and count % HASH_MOD_ITEM_DISPLAY == 0 or hash_regex == HASH.ORACLE_OLD or hash_regex == HASH.CRYPT_GENERIC and IS_WIN:
                    rotator += 1
                    if rotator >= len(ROTATING_CHARS):
                        rotator = 0
                    status = 'current status: %s... %s' % (word.ljust(5)[:5], ROTATING_CHARS[rotator])
                    if not user.startswith(DUMMY_USER_PREFIX):
                        status += ' (user: %s)' % user
                    dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status))

            except KeyboardInterrupt:
                raise

            except (UnicodeEncodeError, UnicodeDecodeError):
                pass # ignore possible encoding problems caused by some words in custom dictionaries

            except Exception, ex:
                print ex
                warnMsg = "there was a problem while hashing entry: %s. " % repr(word)
                warnMsg += "Please report by e-mail to %s" % ML
                logger.critical(warnMsg)

    except KeyboardInterrupt:
        pass

    finally:
        if hasattr(proc_count, 'value'):
            proc_count.value -= 1

def dictionaryAttack(attack_dict):
    suffix_list = [""]
    hash_regexes = []
    results = []
    resumes = []
    processException = False

    for (_, hashes) in attack_dict.items():
        for hash_ in hashes:
            if not hash_:
                continue

            hash_ = hash_.split()[0]
            regex = hashRecognition(hash_)

            if regex and regex not in hash_regexes:
                hash_regexes.append(regex)
                infoMsg = "using hash method '%s'" % __functions__[regex].func_name
                logger.info(infoMsg)

    for hash_regex in hash_regexes:
        keys = set()
        attack_info = []

        for (user, hashes) in attack_dict.items():
            for hash_ in hashes:
                if not hash_:
                    continue

                hash_ = hash_.split()[0]

                if getCompiledRegex(hash_regex).match(hash_):
                    item = None

                    if hash_regex not in (HASH.CRYPT_GENERIC, HASH.WORDPRESS):
                        hash_ = hash_.lower()

                    if hash_regex in (HASH.MYSQL, HASH.MYSQL_OLD, HASH.MD5_GENERIC, HASH.SHA1_GENERIC):
                        item = [(user, hash_), {}]
                    elif hash_regex in (HASH.ORACLE_OLD, HASH.POSTGRES):
                        item = [(user, hash_), {'username': user}]
                    elif hash_regex in (HASH.ORACLE):
                        item = [(user, hash_), {'salt': hash_[-20:]}]
                    elif hash_regex in (HASH.MSSQL, HASH.MSSQL_OLD):
                        item = [(user, hash_), {'salt': hash_[6:14]}]
                    elif hash_regex in (HASH.CRYPT_GENERIC):
                        item = [(user, hash_), {'salt': hash_[0:2]}]
                    elif hash_regex in (HASH.WORDPRESS):
                        item = [(user, hash_), {'salt': hash_[4:12], 'count': 1<<ITOA64.index(hash_[3]), 'prefix': hash_[:12]}]

                    if item and hash_ not in keys:
                        resumed = conf.hashDB.retrieve(hash_)
                        if not resumed:
                            attack_info.append(item)
                        else:
                            infoMsg = "resuming password '%s' for hash '%s'" % (resumed, hash_)
                            if user and not user.startswith(DUMMY_USER_PREFIX):
                                infoMsg += " for user '%s'" % user
                            logger.info(infoMsg)
                            resumes.append((user, hash_, resumed))
                        keys.add(hash_)

        if not attack_info:
            continue

        if not kb.wordlist:
            while not kb.wordlist:

                # the slowest of all methods hence smaller default dict
                if hash_regex in (HASH.ORACLE_OLD, HASH.WORDPRESS):
                    dictPaths = [paths.SMALL_DICT]
                else:
                    dictPaths = [paths.WORDLIST]

                message = "what dictionary do you want to use?\n"
                message += "[1] default dictionary file '%s' (press Enter)\n" % dictPaths[0]
                message += "[2] custom dictionary file\n"
                message += "[3] file with list of dictionary files"
                choice = readInput(message, default="1")

                try:
                    if choice == "2":
                        message = "what's the custom dictionary's location?\n"
                        dictPaths = [readInput(message)]

                        logger.info("using custom dictionary")
                    elif choice == "3":
                        message = "what's the list file location?\n"
                        listPath = readInput(message)
                        checkFile(listPath)
                        dictPaths = getFileItems(listPath)

                        logger.info("using custom list of dictionaries")
                    else:
                        logger.info("using default dictionary")

                    for dictPath in dictPaths:
                        checkFile(dictPath)

                    kb.wordlist = Wordlist(dictPaths)

                    if _multiprocessing:
                        kb.wordlist.lock = _multiprocessing.Lock()

                except sqlmapFilePathException, msg:
                    warnMsg = "there was a problem while loading dictionaries"
                    warnMsg += " ('%s')" % msg
                    logger.critical(warnMsg)

            message = "do you want to use common password suffixes? (slow!) [y/N] "
            test = readInput(message, default="N")

            if test[0] in ("y", "Y"):
                suffix_list += COMMON_PASSWORD_SUFFIXES

        infoMsg = "starting dictionary-based cracking (%s)" % __functions__[hash_regex].func_name
        logger.info(infoMsg)

        for item in attack_info:
            ((user, _), _) = item

            if user and not user.startswith(DUMMY_USER_PREFIX):
                kb.wordlist.append(normalizeUnicode(user))

        if hash_regex in (HASH.MYSQL, HASH.MYSQL_OLD, HASH.MD5_GENERIC, HASH.SHA1_GENERIC):
            for suffix in suffix_list:
                if len(attack_info) == len(results) or processException:
                    break

                if suffix:
                    clearConsoleLine()
                    infoMsg = "using suffix '%s'" % suffix
                    logger.info(infoMsg)

                kb.wordlist.rewind()

                retVal = None
                processes = []

                try:
                    if _multiprocessing and not IS_WIN:
                        if _multiprocessing.cpu_count() > 1:
                            infoMsg = "starting %d processes " % _multiprocessing.cpu_count()
                            singleTimeLogMessage(infoMsg)

                        retVal = _multiprocessing.Queue()
                        count = _multiprocessing.Value('i', _multiprocessing.cpu_count())

                        for i in xrange(_multiprocessing.cpu_count()):
                            p = _multiprocessing.Process(target=__bruteProcessVariantA, args=(attack_info, hash_regex, kb.wordlist, suffix, retVal, i, count))
                            processes.append(p)

                        for p in processes:
                            p.start()

                        for p in processes:
                            p.join()

                    else:
                        warnMsg = "multiprocessing hash cracking is currently "
                        warnMsg += "not supported on this platform"
                        singleTimeWarnMessage(warnMsg)

                        retVal = Queue()
                        __bruteProcessVariantA(attack_info, hash_regex, kb.wordlist, suffix, retVal, 0, 1)

                except KeyboardInterrupt:
                    print
                    processException = True
                    warnMsg = "user aborted during dictionary-based attack phase (Ctrl+C was pressed)"
                    logger.warn(warnMsg)

                    for process in processes:
                        process.terminate()
                        process.join()

                finally:
                    if retVal:
                        conf.hashDB.beginTransaction()

                        while not retVal.empty():
                            _, hash_, word = item = retVal.get(block=False)
                            conf.hashDB.write(hash_, word)
                            results.append(item)

                        conf.hashDB.endTransaction()

            clearConsoleLine()

        else:
            for ((user, hash_), kwargs) in attack_info:
                if processException:
                    break

                count = 0
                found = False

                for suffix in suffix_list:
                    if found or processException:
                        break

                    if suffix:
                        clearConsoleLine()
                        infoMsg = "using suffix '%s'" % suffix
                        logger.info(infoMsg)

                    kb.wordlist.rewind()

                    retVal = None
                    processes = []

                    try:
                        if _multiprocessing and not IS_WIN:
                            if _multiprocessing.cpu_count() > 1:
                                infoMsg = "starting %d processes " % _multiprocessing.cpu_count()
                                singleTimeLogMessage(infoMsg)

                            retVal = _multiprocessing.Queue()
                            found_ = _multiprocessing.Value('i', False)
                            count = _multiprocessing.Value('i', _multiprocessing.cpu_count())

                            for i in xrange(_multiprocessing.cpu_count()):
                                p = _multiprocessing.Process(target=__bruteProcessVariantB, args=(user, hash_, kwargs, hash_regex, kb.wordlist, suffix, retVal, found_, i, count))
                                processes.append(p)

                            for p in processes:
                                p.start()

                            for p in processes:
                                p.join()

                            found = found_.value != 0

                        else:
                            warnMsg = "multiprocessing hash cracking is currently "
                            warnMsg += "not supported on this platform"
                            singleTimeWarnMessage(warnMsg)

                            class Value():
                                pass

                            retVal = Queue()
                            found_ = Value()
                            found_.value = False

                            __bruteProcessVariantB(user, hash_, kwargs, hash_regex, kb.wordlist, suffix, retVal, found_, 0, 1)

                            found = found_.value

                    except KeyboardInterrupt:
                        print
                        processException = True
                        warnMsg = "user aborted during dictionary-based attack phase (Ctrl+C was pressed)"
                        logger.warn(warnMsg)

                        for process in processes:
                            process.terminate()
                            process.join()

                    finally:
                        if retVal:
                            conf.hashDB.beginTransaction()

                            while not retVal.empty():
                                _, hash_, word = item = retVal.get(block=False)
                                conf.hashDB.write(hash_, word)
                                results.append(item)

                            conf.hashDB.endTransaction()

                clearConsoleLine()

    results.extend(resumes)

    if len(hash_regexes) == 0:
        warnMsg = "unknown hash format. "
        warnMsg += "Please report by e-mail to %s" % ML
        logger.warn(warnMsg)

    if len(results) == 0:
        warnMsg = "no clear password(s) found"
        logger.warn(warnMsg)

    return results
