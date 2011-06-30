#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

try:
    from crypt import crypt
except ImportError, _:
    from extra.fcrypt.fcrypt import crypt

import os
import re
import time

from hashlib import md5
from hashlib import sha1
from zipfile import ZipFile

from extra.pydes.pyDes import des
from extra.pydes.pyDes import CBC
from lib.core.common import checkFile
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import getCompiledRegex
from lib.core.common import getFileItems
from lib.core.common import Backend
from lib.core.common import getCompiledRegex
from lib.core.common import getPublicTypeMembers
from lib.core.common import normalizeUnicode
from lib.core.common import paths
from lib.core.common import readInput
from lib.core.common import singleTimeLogMessage
from lib.core.common import Wordlist
from lib.core.convert import hexdecode
from lib.core.convert import hexencode
from lib.core.convert import utf8encode
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import HASH
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapUserQuitException
from lib.core.settings import COMMON_PASSWORD_SUFFIXES
from lib.core.settings import DUMMY_USER_PREFIX
from lib.core.settings import GENERAL_IP_ADDRESS_REGEX
from lib.core.settings import HASH_MOD_ITEM_DISPLAY
from lib.core.settings import IS_WIN
from lib.core.settings import ML
from lib.core.settings import UNICODE_ENCODING

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
                    HASH.CRYPT_GENERIC: crypt_generic_passwd
                }

def attackCachedUsersPasswords():
    if kb.data.cachedUsersPasswords:
        results = dictionaryAttack(kb.data.cachedUsersPasswords)

        for (user, hash_, password) in results:
            for i in xrange(len(kb.data.cachedUsersPasswords[user])):
                if kb.data.cachedUsersPasswords[user][i] and hash_.lower() in kb.data.cachedUsersPasswords[user][i].lower():
                    kb.data.cachedUsersPasswords[user][i] += "%s    clear-text password: %s" % ('\n' if kb.data.cachedUsersPasswords[user][i][-1] != '\n' else '', password)

def attackDumpedTable():
    if kb.data.dumpedTable:
        table = kb.data.dumpedTable
        columns = table.keys()
        count = table["__infos__"]["count"]

        colUser = ''
        attack_dict = {}

        for column in columns:
            if column and column.lower() in ('user', 'username', 'user_name'):
                colUser = column
                break

        for i in range(count):
            for column in columns:
                if column == colUser or column == '__infos__':
                    continue

                if len(table[column]['values']) <= i:
                    continue

                value = table[column]['values'][i]

                if hashRecognition(value):
                    if colUser:
                        if table[colUser]['values'][i] not in attack_dict:
                            attack_dict[table[colUser]['values'][i]] = []

                        attack_dict[table[colUser]['values'][i]].append(value)
                    else:
                        attack_dict['%s%d' % (DUMMY_USER_PREFIX, i)] = [value]

        if attack_dict:
            message = "recognized possible password hash values. "
            message += "do you want to use dictionary attack on retrieved table items? [Y/n/q]"
            test = readInput(message, default="Y")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException

            results = dictionaryAttack(attack_dict)

            for (user, hash_, password) in results:
                for i in range(count):
                    for column in columns:
                        if column == colUser or column == '__infos__':
                            continue
                        if len(table[column]['values']) <= i:
                            continue

                        value = table[column]['values'][i]

                        if all(map(lambda x: x, [value, hash_])) and value.lower() == hash_.lower():
                            table[column]['values'][i] += " (%s)" % password
                            table[column]['length'] = max(table[column]['length'], len(table[column]['values'][i]))

def hashRecognition(value):
    retVal = None

    if isinstance(value, basestring):
        for name, regex in getPublicTypeMembers(HASH):
            # Hashes for Oracle and old MySQL look the same hence these checks
            if Backend.isDbms(DBMS.ORACLE) and regex == HASH.MYSQL_OLD:
                continue
            elif Backend.isDbms(DBMS.MYSQL) and regex == HASH.ORACLE_OLD:
                continue
            elif regex == HASH.CRYPT_GENERIC:
                if any([getCompiledRegex(GENERAL_IP_ADDRESS_REGEX).match(value), value.lower() == value, value.upper() == value, value.isdigit()]):
                    continue
            elif getCompiledRegex(regex).match(value):
                retVal = regex
                break

    return retVal

def dictionaryAttack(attack_dict):
    suffix_list = [""]
    hash_regexes = []
    results = []

    for (_, hashes) in attack_dict.items():
        for hash_ in hashes:
            if not hash_:
                continue

            hash_ = hash_.split()[0]
            regex = hashRecognition(hash_)

            if regex and regex not in hash_regexes:
                hash_regexes.append(regex)
                infoMsg = "using hash method: '%s'" % __functions__[regex].func_name
                logger.info(infoMsg)

    for hash_regex in hash_regexes:
        attack_info = []

        for (user, hashes) in attack_dict.items():
            for hash_ in hashes:
                if not hash_:
                    continue

                hash_ = hash_.split()[0]

                if getCompiledRegex(hash_regex).match(hash_):
                    hash_ = hash_.lower()

                    if hash_regex in (HASH.MYSQL, HASH.MYSQL_OLD, HASH.MD5_GENERIC, HASH.SHA1_GENERIC):
                        attack_info.append([(user, hash_), {}])

                    elif hash_regex in (HASH.ORACLE_OLD, HASH.POSTGRES):
                        attack_info.append([(user, hash_), {'username': user}])

                    elif hash_regex in (HASH.ORACLE):
                        attack_info.append([(user, hash_), {'salt': hash_[-20:]}])

                    elif hash_regex in (HASH.MSSQL, HASH.MSSQL_OLD):
                        attack_info.append([(user, hash_), {'salt': hash_[6:14]}])

                    elif hash_regex in (HASH.CRYPT_GENERIC):
                        attack_info.append([(user, hash_), {'salt': hash_[0:2]}])

        if not attack_info:
            continue

        if not kb.wordlist:
            while not kb.wordlist:
                message = "what dictionary do you want to use?\n"
                message += "[1] Default (Press Enter)\n"
                message += "[2] Custom\n"
                message += "[3] File with list of dictionary files"
                choice = readInput(message, default="1")

                try:
                    if choice == "2":
                        message = "what's the custom dictionary's location?\n"
                        dictPaths = [readInput(message)]
                    elif choice == "3":
                        message = "what's the list file location?\n"
                        listPath = readInput(message)
                        checkFile(listPath)
                        dictPaths = getFileItems(listPath)
                    else:
                        if hash_regex == HASH.ORACLE_OLD: #it's the slowest of all methods hence smaller default dict
                            dictPaths = [paths.ORACLE_DEFAULT_PASSWD]
                        else:
                            dictPaths = [paths.WORDLIST]

                    for dictPath in dictPaths:
                        checkFile(dictPath)

                    kb.wordlist = Wordlist(dictPaths)

                except sqlmapFilePathException, msg:
                    warnMsg = "there was a problem while loading dictionaries"
                    warnMsg += " ('%s')" % msg
                    logger.critical(warnMsg)

            message = "do you want to use common password suffixes? (slow!) [y/N] "
            test = readInput(message, default="N")

            if test[0] in ("y", "Y"):
                suffix_list += COMMON_PASSWORD_SUFFIXES

        infoMsg = "starting dictionary attack (%s)" % __functions__[hash_regex].func_name
        logger.info(infoMsg)

        for item in attack_info:
            ((user, _), _) = item

            if user:
                kb.wordlist.append(normalizeUnicode(user))

        if hash_regex in (HASH.MYSQL, HASH.MYSQL_OLD, HASH.MD5_GENERIC, HASH.SHA1_GENERIC):
            count = 0

            for suffix in suffix_list:
                if not attack_info:
                    break

                if suffix:
                    clearConsoleLine()
                    infoMsg = "using suffix: '%s'" % suffix
                    logger.info(infoMsg)

                kb.wordlist.rewind()

                for word in kb.wordlist:
                    if not attack_info:
                        break

                    count += 1

                    if not isinstance(word, basestring):
                        continue

                    if suffix:
                        word = word + suffix

                    try:
                        current = __functions__[hash_regex](password = word, uppercase = False)

                        for item in attack_info:
                            ((user, hash_), _) = item

                            if hash_ == current:
                                results.append((user, hash_, word))
                                clearConsoleLine()

                                infoMsg = "[%s] [INFO] found: '%s'" % (time.strftime("%X"), word)

                                if user and not user.startswith(DUMMY_USER_PREFIX):
                                    infoMsg += " for user: '%s'\n" % user
                                else:
                                    infoMsg += " for hash: '%s'\n" % hash_

                                dataToStdout(infoMsg, True)

                                attack_info.remove(item)

                            elif count % HASH_MOD_ITEM_DISPLAY == 0 or hash_regex in (HASH.ORACLE_OLD) or hash_regex == HASH.CRYPT_GENERIC and IS_WIN:
                                status = 'current status: %d%s (%s...)' % (kb.wordlist.percentage(), '%', word.ljust(5)[:5])
                                dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status))

                    except KeyboardInterrupt:
                        print
                        warnMsg = "user aborted during dictionary attack phase"
                        logger.warn(warnMsg)
                        return results

                    except:
                        warnMsg = "there was a problem while hashing entry: %s. " % repr(word)
                        warnMsg += "Please report by e-mail to %s." % ML
                        logger.critical(warnMsg)

            clearConsoleLine()

        else:
            for ((user, hash_), kwargs) in attack_info:
                count = 0
                found = False

                for suffix in suffix_list:
                    if found:
                        break

                    if suffix:
                        clearConsoleLine()
                        infoMsg = "using suffix: '%s'" % suffix
                        logger.info(infoMsg)

                    kb.wordlist.rewind()

                    for word in kb.wordlist:
                        current = __functions__[hash_regex](password = word, uppercase = False, **kwargs)
                        count += 1

                        if not isinstance(word, basestring):
                            continue

                        if suffix:
                            word = word + suffix

                        try:
                            if hash_ == current:
                                if regex == HASH.ORACLE_OLD: #only for cosmetic purposes
                                    word = word.upper()
                                results.append((user, hash_, word))
                                clearConsoleLine()

                                infoMsg = "[%s] [INFO] found: '%s'" % (time.strftime("%X"), word)

                                if user and not user.startswith(DUMMY_USER_PREFIX):
                                    infoMsg += " for user: '%s'\n" % user
                                else:
                                    infoMsg += " for hash: '%s'\n" % hash_

                                dataToStdout(infoMsg, True)

                                found = True
                                break
                            elif count % HASH_MOD_ITEM_DISPLAY == 0 or hash_regex in (HASH.ORACLE_OLD) or hash_regex == HASH.CRYPT_GENERIC and IS_WIN:
                                status = 'current status: %d%s (%s...)' % (kb.wordlist.percentage(), '%', word.ljust(5)[:5])
                                if not user.startswith(DUMMY_USER_PREFIX):
                                    status += ' (user: %s)' % user
                                dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status))

                        except KeyboardInterrupt:
                            print
                            warnMsg = "user aborted during dictionary attack phase"
                            logger.warn(warnMsg)
                            return results

                        except:
                            warnMsg = "there was a problem while hashing entry: %s. " % repr(word)
                            warnMsg += "Please report by e-mail to %s." % ML
                            logger.critical(warnMsg)

                clearConsoleLine()

    if len(hash_regexes) == 0:
        warnMsg = "unknown hash Format. "
        warnMsg += "Please report by e-mail to %s." % ML
        logger.warn(warnMsg)

    if len(results) == 0:
        warnMsg = "no clear password(s) found"
        logger.warn(warnMsg)

    return results
