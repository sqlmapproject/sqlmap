#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

try:
    from crypt import crypt
except:  # removed ImportError because of https://github.com/sqlmapproject/sqlmap/issues/3171
    from thirdparty.fcrypt.fcrypt import crypt

try:
    from Crypto.Cipher.DES import MODE_CBC as CBC
    from Crypto.Cipher.DES import new as des
except:
    from thirdparty.pydes.pyDes import CBC
    from thirdparty.pydes.pyDes import des

_multiprocessing = None

import base64
import binascii
import gc
import math
import os
import re
import tempfile
import time
import zipfile

from hashlib import md5
from hashlib import sha1
from hashlib import sha224
from hashlib import sha256
from hashlib import sha384
from hashlib import sha512

from lib.core.common import Backend
from lib.core.common import checkFile
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import getFileItems
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import isZipFile
from lib.core.common import normalizeUnicode
from lib.core.common import openFile
from lib.core.common import paths
from lib.core.common import readInput
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.convert import decodeBase64
from lib.core.convert import decodeHex
from lib.core.convert import encodeHex
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import OrderedSet
from lib.core.enums import DBMS
from lib.core.enums import HASH
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import COMMON_PASSWORD_SUFFIXES
from lib.core.settings import COMMON_USER_COLUMNS
from lib.core.settings import DEV_EMAIL_ADDRESS
from lib.core.settings import DUMMY_USER_PREFIX
from lib.core.settings import HASH_BINARY_COLUMNS_REGEX
from lib.core.settings import HASH_EMPTY_PASSWORD_MARKER
from lib.core.settings import HASH_MOD_ITEM_DISPLAY
from lib.core.settings import HASH_RECOGNITION_QUIT_THRESHOLD
from lib.core.settings import INVALID_UNICODE_CHAR_FORMAT
from lib.core.settings import IS_WIN
from lib.core.settings import ITOA64
from lib.core.settings import NULL
from lib.core.settings import ROTATING_CHARS
from lib.core.settings import UNICODE_ENCODING
from lib.core.wordlist import Wordlist
from thirdparty import six
from thirdparty.colorama.initialise import init as coloramainit
from thirdparty.six.moves import queue as _queue

def mysql_passwd(password, uppercase=True):
    """
    Reference(s):
        https://web.archive.org/web/20120215205312/http://csl.sublevel3.org/mysql-password-function/

    >>> mysql_passwd(password='testpass', uppercase=True)
    '*00E247AC5F9AF26AE0194B41E1E769DEE1429A29'
    """

    password = getBytes(password)

    retVal = "*%s" % sha1(sha1(password).digest()).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def mysql_old_passwd(password, uppercase=True):  # prior to version '4.1'
    """
    Reference(s):
        https://web.archive.org/web/20091205000600/http://www.sfr-fresh.com/unix/privat/tpop3d-1.5.5.tar.gz:a/tpop3d-1.5.5/password.c
        https://github.com/pwnieexpress/pwn_plug_sources/blob/master/src/darkmysqli/DarkMySQLi.py

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

    username = getBytes(username)
    password = getBytes(password)

    retVal = "md5%s" % md5(password + username).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def mssql_new_passwd(password, salt, uppercase=False):  # since version '2012'
    """
    Reference(s):
        http://hashcat.net/forum/thread-1474.html
        https://sqlity.net/en/2460/sql-password-hash/

    >>> mssql_new_passwd(password='testpass', salt='4086ceb6', uppercase=False)
    '0x02004086ceb6eb051cdbc5bdae68ffc66c918d4977e592f6bdfc2b444a7214f71fa31c35902c5b7ae773ed5f4c50676d329120ace32ee6bc81c24f70711eb0fc6400e85ebf25'
    """

    binsalt = decodeHex(salt)
    unistr = b"".join((_.encode(UNICODE_ENCODING) + b"\0") if ord(_) < 256 else _.encode(UNICODE_ENCODING) for _ in password)

    retVal = "0200%s%s" % (salt, sha512(unistr + binsalt).hexdigest())

    return "0x%s" % (retVal.upper() if uppercase else retVal.lower())

def mssql_passwd(password, salt, uppercase=False):  # versions '2005' and '2008'
    """
    Reference(s):
        http://www.leidecker.info/projects/phrasendrescher/mssql.c
        https://www.evilfingers.com/tools/GSAuditor.php

    >>> mssql_passwd(password='testpass', salt='4086ceb6', uppercase=False)
    '0x01004086ceb60c90646a8ab9889fe3ed8e5c150b5460ece8425a'
    """

    binsalt = decodeHex(salt)
    unistr = b"".join((_.encode(UNICODE_ENCODING) + b"\0") if ord(_) < 256 else _.encode(UNICODE_ENCODING) for _ in password)

    retVal = "0100%s%s" % (salt, sha1(unistr + binsalt).hexdigest())

    return "0x%s" % (retVal.upper() if uppercase else retVal.lower())

def mssql_old_passwd(password, salt, uppercase=True):  # version '2000' and before
    """
    Reference(s):
        www.exploit-db.com/download_pdf/15537/
        http://www.leidecker.info/projects/phrasendrescher/mssql.c
        https://www.evilfingers.com/tools/GSAuditor.php

    >>> mssql_old_passwd(password='testpass', salt='4086ceb6', uppercase=True)
    '0x01004086CEB60C90646A8AB9889FE3ED8E5C150B5460ECE8425AC7BB7255C0C81D79AA5D0E93D4BB077FB9A51DA0'
    """

    binsalt = decodeHex(salt)
    unistr = b"".join((_.encode(UNICODE_ENCODING) + b"\0") if ord(_) < 256 else _.encode(UNICODE_ENCODING) for _ in password)

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

    binsalt = decodeHex(salt)
    password = getBytes(password)

    retVal = "s:%s%s" % (sha1(password + binsalt).hexdigest(), salt)

    return retVal.upper() if uppercase else retVal.lower()

def oracle_old_passwd(password, username, uppercase=True):  # prior to version '11g'
    """
    Reference(s):
        http://www.notesbit.com/index.php/scripts-oracle/oracle-11g-new-password-algorithm-is-revealed-by-seclistsorg/

    >>> oracle_old_passwd(password='tiger', username='scott', uppercase=True)
    'F894844C34402B67'
    """

    IV, pad = b"\0" * 8, b"\0"

    unistr = b"".join((b"\0" + _.encode(UNICODE_ENCODING)) if ord(_) < 256 else _.encode(UNICODE_ENCODING) for _ in (username + password).upper())

    if des.__module__ == "Crypto.Cipher.DES":
        unistr += b"\0" * ((8 - len(unistr) % 8) & 7)
        cipher = des(decodeHex("0123456789ABCDEF"), CBC, iv=IV)
        encrypted = cipher.encrypt(unistr)
        cipher = des(encrypted[-8:], CBC, iv=IV)
        encrypted = cipher.encrypt(unistr)
    else:
        cipher = des(decodeHex("0123456789ABCDEF"), CBC, IV, pad)
        encrypted = cipher.encrypt(unistr)
        cipher = des(encrypted[-8:], CBC, IV, pad)
        encrypted = cipher.encrypt(unistr)

    retVal = encodeHex(encrypted[-8:], binary=False)

    return retVal.upper() if uppercase else retVal.lower()

def md5_generic_passwd(password, uppercase=False):
    """
    >>> md5_generic_passwd(password='testpass', uppercase=False)
    '179ad45c6ce2cb97cf1029e212046e81'
    """

    password = getBytes(password)

    retVal = md5(password).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def sha1_generic_passwd(password, uppercase=False):
    """
    >>> sha1_generic_passwd(password='testpass', uppercase=False)
    '206c80413b9a96c1312cc346b7d2517b84463edd'
    """

    password = getBytes(password)

    retVal = sha1(password).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def apache_sha1_passwd(password, **kwargs):
    """
    >>> apache_sha1_passwd(password='testpass')
    '{SHA}IGyAQTualsExLMNGt9JRe4RGPt0='
    """

    password = getBytes(password)

    return "{SHA}%s" % getText(base64.b64encode(sha1(password).digest()))

def ssha_passwd(password, salt, **kwargs):
    """
    >>> ssha_passwd(password='testpass', salt='salt')
    '{SSHA}mU1HPTvnmoXOhE4ROHP6sWfbfoRzYWx0'
    """

    password = getBytes(password)
    salt = getBytes(salt)

    return "{SSHA}%s" % getText(base64.b64encode(sha1(password + salt).digest() + salt))

def ssha256_passwd(password, salt, **kwargs):
    """
    >>> ssha256_passwd(password='testpass', salt='salt')
    '{SSHA256}hhubsLrO/Aje9F/kJrgv5ZLE40UmTrVWvI7Dt6InP99zYWx0'
    """

    password = getBytes(password)
    salt = getBytes(salt)

    return "{SSHA256}%s" % getText(base64.b64encode(sha256(password + salt).digest() + salt))

def ssha512_passwd(password, salt, **kwargs):
    """
    >>> ssha512_passwd(password='testpass', salt='salt')
    '{SSHA512}mCUSLfPMhXCQOJl9WHW/QMn9v9sjq7Ht/Wk7iVau8vLOfh+PeynkGMikqIE8sStFd0khdfcCD8xZmC6UyjTxsHNhbHQ='
    """

    password = getBytes(password)
    salt = getBytes(salt)

    return "{SSHA512}%s" % getText(base64.b64encode(sha512(password + salt).digest() + salt))

def sha224_generic_passwd(password, uppercase=False):
    """
    >>> sha224_generic_passwd(password='testpass', uppercase=False)
    '648db6019764b598f75ab6b7616d2e82563a00eb1531680e19ac4c6f'
    """

    retVal = sha224(getBytes(password)).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def sha256_generic_passwd(password, uppercase=False):
    """
    >>> sha256_generic_passwd(password='testpass', uppercase=False)
    '13d249f2cb4127b40cfa757866850278793f814ded3c587fe5889e889a7a9f6c'
    """

    retVal = sha256(getBytes(password)).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def sha384_generic_passwd(password, uppercase=False):
    """
    >>> sha384_generic_passwd(password='testpass', uppercase=False)
    '6823546e56adf46849343be991d4b1be9b432e42ed1b4bb90635a0e4b930e49b9ca007bc3e04bf0a4e0df6f1f82769bf'
    """

    retVal = sha384(getBytes(password)).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def sha512_generic_passwd(password, uppercase=False):
    """
    >>> sha512_generic_passwd(password='testpass', uppercase=False)
    '78ddc8555bb1677ff5af75ba5fc02cb30bb592b0610277ae15055e189b77fe3fda496e5027a3d99ec85d54941adee1cc174b50438fdc21d82d0a79f85b58cf44'
    """

    retVal = sha512(getBytes(password)).hexdigest()

    return retVal.upper() if uppercase else retVal.lower()

def crypt_generic_passwd(password, salt, **kwargs):
    """
    Reference(s):
        http://docs.python.org/library/crypt.html
        http://helpful.knobs-dials.com/index.php/Hashing_notes
        http://php.net/manual/en/function.crypt.php
        http://carey.geek.nz/code/python-fcrypt/

    >>> crypt_generic_passwd(password='rasmuslerdorf', salt='rl', uppercase=False)
    'rl.3StKT.4T8M'
    """

    return getText(crypt(password, salt))

def unix_md5_passwd(password, salt, magic="$1$", **kwargs):
    """
    Reference(s):
        http://www.sabren.net/code/python/crypt/md5crypt.py

    >>> unix_md5_passwd(password='testpass', salt='aD9ZLmkp')
    '$1$aD9ZLmkp$DRM5a7rRZGyuuOPOjTEk61'
    """

    def _encode64(value, count):
        output = ""

        while (count - 1 >= 0):
            count = count - 1
            output += ITOA64[value & 0x3f]
            value = value >> 6

        return output

    password = getBytes(password)
    magic = getBytes(magic)
    salt = getBytes(salt)

    salt = salt[:8]
    ctx = password + magic + salt
    final = md5(password + salt + password).digest()

    for pl in xrange(len(password), 0, -16):
        if pl > 16:
            ctx = ctx + final[:16]
        else:
            ctx = ctx + final[:pl]

    i = len(password)
    while i:
        if i & 1:
            ctx = ctx + b'\x00'  # if ($i & 1) { $ctx->add(pack("C", 0)); }
        else:
            ctx = ctx + password[0:1]
        i = i >> 1

    final = md5(ctx).digest()

    for i in xrange(1000):
        ctx1 = b""

        if i & 1:
            ctx1 = ctx1 + password
        else:
            ctx1 = ctx1 + final[:16]

        if i % 3:
            ctx1 = ctx1 + salt

        if i % 7:
            ctx1 = ctx1 + password

        if i & 1:
            ctx1 = ctx1 + final[:16]
        else:
            ctx1 = ctx1 + password

        final = md5(ctx1).digest()

    hash_ = _encode64((int(ord(final[0:1])) << 16) | (int(ord(final[6:7])) << 8) | (int(ord(final[12:13]))), 4)
    hash_ = hash_ + _encode64((int(ord(final[1:2])) << 16) | (int(ord(final[7:8])) << 8) | (int(ord(final[13:14]))), 4)
    hash_ = hash_ + _encode64((int(ord(final[2:3])) << 16) | (int(ord(final[8:9])) << 8) | (int(ord(final[14:15]))), 4)
    hash_ = hash_ + _encode64((int(ord(final[3:4])) << 16) | (int(ord(final[9:10])) << 8) | (int(ord(final[15:16]))), 4)
    hash_ = hash_ + _encode64((int(ord(final[4:5])) << 16) | (int(ord(final[10:11])) << 8) | (int(ord(final[5:6]))), 4)
    hash_ = hash_ + _encode64((int(ord(final[11:12]))), 2)

    return getText(magic + salt + b'$' + getBytes(hash_))

def joomla_passwd(password, salt, **kwargs):
    """
    Reference: https://stackoverflow.com/a/10428239

    >>> joomla_passwd(password='testpass', salt='6GGlnaquVXI80b3HRmSyE3K1wEFFaBIf')
    'e3d5794da74e917637332e0d21b76328:6GGlnaquVXI80b3HRmSyE3K1wEFFaBIf'
    """

    return "%s:%s" % (md5(getBytes(password) + getBytes(salt)).hexdigest(), salt)

def django_md5_passwd(password, salt, **kwargs):
    """
    Reference: https://github.com/jay0lee/GAM/blob/master/src/passlib/handlers/django.py

    >>> django_md5_passwd(password='testpass', salt='salt')
    'md5$salt$972141bcbcb6a0acc96e92309175b3c5'
    """

    return "md5$%s$%s" % (salt, md5(getBytes(salt) + getBytes(password)).hexdigest())

def django_sha1_passwd(password, salt, **kwargs):
    """
    Reference: https://github.com/jay0lee/GAM/blob/master/src/passlib/handlers/django.py

    >>> django_sha1_passwd(password='testpass', salt='salt')
    'sha1$salt$6ce0e522aba69d8baa873f01420fccd0250fc5b2'
    """

    return "sha1$%s$%s" % (salt, sha1(getBytes(salt) + getBytes(password)).hexdigest())

def vbulletin_passwd(password, salt, **kwargs):
    """
    Reference: https://stackoverflow.com/a/2202810

    >>> vbulletin_passwd(password='testpass', salt='salt')
    '85c4d8ea77ebef2236fb7e9d24ba9482:salt'
    """

    return "%s:%s" % (md5(binascii.hexlify(md5(getBytes(password)).digest()) + getBytes(salt)).hexdigest(), salt)

def phpass_passwd(password, salt, count, prefix, **kwargs):
    """
    Reference(s):
        https://web.archive.org/web/20120219120128/packetstormsecurity.org/files/74448/phpassbrute.py.txt
        http://scriptserver.mainframe8.com/wordpress_password_hasher.php
        https://www.openwall.com/phpass/
        https://github.com/jedie/django-phpBB3/blob/master/django_phpBB3/hashers.py

    >>> phpass_passwd(password='testpass', salt='aD9ZLmkp', count=2048, prefix='$P$')
    '$P$9aD9ZLmkpsN4A83G8MefaaP888gVKX0'
    >>> phpass_passwd(password='testpass', salt='Pb1j9gSb', count=2048, prefix='$H$')
    '$H$9Pb1j9gSb/u3EVQ.4JDZ3LqtN44oIx/'
    >>> phpass_passwd(password='testpass', salt='iwtD/g.K', count=128, prefix='$S$')
    '$S$5iwtD/g.KZT2rwC9DASy/mGYAThkSd3lBFdkONi1Ig1IEpBpqG8W'
    """

    def _encode64(input_, count):
        output = ''
        i = 0

        while i < count:
            value = (input_[i] if isinstance(input_[i], int) else ord(input_[i]))
            i += 1
            output = output + ITOA64[value & 0x3f]

            if i < count:
                value = value | ((input_[i] if isinstance(input_[i], int) else ord(input_[i])) << 8)

            output = output + ITOA64[(value >> 6) & 0x3f]

            i += 1
            if i >= count:
                break

            if i < count:
                value = value | ((input_[i] if isinstance(input_[i], int) else ord(input_[i])) << 16)

            output = output + ITOA64[(value >> 12) & 0x3f]

            i += 1
            if i >= count:
                break

            output = output + ITOA64[(value >> 18) & 0x3f]

        return output

    password = getBytes(password)
    f = {"$P$": md5, "$H$": md5, "$Q$": sha1, "$S$": sha512}[prefix]

    cipher = f(getBytes(salt))
    cipher.update(password)
    hash_ = cipher.digest()

    for i in xrange(count):
        _ = f(hash_)
        _.update(password)
        hash_ = _.digest()

    retVal = "%s%s%s%s" % (prefix, ITOA64[int(math.log(count, 2))], salt, _encode64(hash_, len(hash_)))

    if prefix == "$S$":
        # Reference: https://api.drupal.org/api/drupal/includes%21password.inc/constant/DRUPAL_HASH_LENGTH/7.x
        retVal = retVal[:55]

    return retVal

__functions__ = {
    HASH.MYSQL: mysql_passwd,
    HASH.MYSQL_OLD: mysql_old_passwd,
    HASH.POSTGRES: postgres_passwd,
    HASH.MSSQL: mssql_passwd,
    HASH.MSSQL_OLD: mssql_old_passwd,
    HASH.MSSQL_NEW: mssql_new_passwd,
    HASH.ORACLE: oracle_passwd,
    HASH.ORACLE_OLD: oracle_old_passwd,
    HASH.MD5_GENERIC: md5_generic_passwd,
    HASH.SHA1_GENERIC: sha1_generic_passwd,
    HASH.SHA224_GENERIC: sha224_generic_passwd,
    HASH.SHA256_GENERIC: sha256_generic_passwd,
    HASH.SHA384_GENERIC: sha384_generic_passwd,
    HASH.SHA512_GENERIC: sha512_generic_passwd,
    HASH.CRYPT_GENERIC: crypt_generic_passwd,
    HASH.JOOMLA: joomla_passwd,
    HASH.DJANGO_MD5: django_md5_passwd,
    HASH.DJANGO_SHA1: django_sha1_passwd,
    HASH.PHPASS: phpass_passwd,
    HASH.APACHE_MD5_CRYPT: unix_md5_passwd,
    HASH.UNIX_MD5_CRYPT: unix_md5_passwd,
    HASH.APACHE_SHA1: apache_sha1_passwd,
    HASH.VBULLETIN: vbulletin_passwd,
    HASH.VBULLETIN_OLD: vbulletin_passwd,
    HASH.SSHA: ssha_passwd,
    HASH.SSHA256: ssha256_passwd,
    HASH.SSHA512: ssha512_passwd,
    HASH.MD5_BASE64: md5_generic_passwd,
    HASH.SHA1_BASE64: sha1_generic_passwd,
    HASH.SHA256_BASE64: sha256_generic_passwd,
    HASH.SHA512_BASE64: sha512_generic_passwd,
}

def _finalize(retVal, results, processes, attack_info=None):
    if _multiprocessing:
        gc.enable()

    # NOTE: https://github.com/sqlmapproject/sqlmap/issues/4367
    # NOTE: https://dzone.com/articles/python-101-creating-multiple-processes
    for process in processes:
        try:
            process.terminate()
            process.join()
        except (OSError, AttributeError):
            pass

    if retVal:
        removals = set()

        if conf.hashDB:
            conf.hashDB.beginTransaction()

        while not retVal.empty():
            user, hash_, word = item = retVal.get(block=False)
            results.append(item)
            removals.add((user, hash_))
            hashDBWrite(hash_, word)

        for item in attack_info or []:
            if (item[0][0], item[0][1]) in removals:
                attack_info.remove(item)

        if conf.hashDB:
            conf.hashDB.endTransaction()

        if hasattr(retVal, "close"):
            retVal.close()

def storeHashesToFile(attack_dict):
    if not attack_dict:
        return

    items = OrderedSet()

    for user, hashes in attack_dict.items():
        for hash_ in hashes:
            hash_ = hash_.split()[0] if hash_ and hash_.strip() else hash_
            if hash_ and hash_ != NULL and hashRecognition(hash_):
                item = None
                if user and not user.startswith(DUMMY_USER_PREFIX):
                    item = "%s:%s\n" % (user, hash_)
                else:
                    item = "%s\n" % hash_

                if item and item not in items:
                    items.add(item)

    if kb.choices.storeHashes is None:
        message = "do you want to store hashes to a temporary file "
        message += "for eventual further processing with other tools [y/N] "

        kb.choices.storeHashes = readInput(message, default='N', boolean=True)

    if items and kb.choices.storeHashes:
        handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.HASHES, suffix=".txt")
        os.close(handle)

        infoMsg = "writing hashes to a temporary file '%s' " % filename
        logger.info(infoMsg)

        with openFile(filename, "w+") as f:
            for item in items:
                try:
                    f.write(item)
                except (UnicodeError, TypeError):
                    pass

def attackCachedUsersPasswords():
    if kb.data.cachedUsersPasswords:
        results = dictionaryAttack(kb.data.cachedUsersPasswords)

        lut = {}
        for (_, hash_, password) in results:
            lut[hash_.lower()] = password

        for user in kb.data.cachedUsersPasswords:
            for i in xrange(len(kb.data.cachedUsersPasswords[user])):
                if (kb.data.cachedUsersPasswords[user][i] or "").strip():
                    value = kb.data.cachedUsersPasswords[user][i].lower().split()[0]
                    if value in lut:
                        kb.data.cachedUsersPasswords[user][i] += "%s    clear-text password: %s" % ('\n' if kb.data.cachedUsersPasswords[user][i][-1] != '\n' else '', lut[value])

def attackDumpedTable():
    if kb.data.dumpedTable:
        table = kb.data.dumpedTable
        columns = list(table.keys())
        count = table["__infos__"]["count"]

        if not count:
            return

        debugMsg = "analyzing table dump for possible password hashes"
        logger.debug(debugMsg)

        found = False
        col_user = ''
        col_passwords = set()
        attack_dict = {}
        binary_fields = OrderedSet()
        replacements = {}

        for column in sorted(columns, key=len, reverse=True):
            if column and column.lower() in COMMON_USER_COLUMNS:
                col_user = column
                break

        for column in columns:
            if column != "__infos__" and table[column]["values"]:
                if all(INVALID_UNICODE_CHAR_FORMAT.split('%')[0] in (value or "") for value in table[column]["values"]):
                    binary_fields.add(column)

        if binary_fields:
            _ = ','.join(binary_fields)
            warnMsg = "potential binary fields detected ('%s'). In case of any problems you are " % _
            warnMsg += "advised to rerun table dump with '--fresh-queries --binary-fields=\"%s\"'" % _
            logger.warning(warnMsg)

        for i in xrange(count):
            if not found and i > HASH_RECOGNITION_QUIT_THRESHOLD:
                break

            for column in columns:
                if column == col_user or column == "__infos__":
                    continue

                if len(table[column]["values"]) <= i:
                    continue

                if conf.binaryFields and column in conf.binaryFields:
                    continue

                value = table[column]["values"][i]

                if column in binary_fields and re.search(HASH_BINARY_COLUMNS_REGEX, column) is not None:
                    previous = value
                    value = encodeHex(getBytes(value), binary=False)
                    replacements[value] = previous

                if hashRecognition(value):
                    found = True

                    if col_user and i < len(table[col_user]["values"]):
                        if table[col_user]["values"][i] not in attack_dict:
                            attack_dict[table[col_user]["values"][i]] = []

                        attack_dict[table[col_user]["values"][i]].append(value)
                    else:
                        attack_dict["%s%d" % (DUMMY_USER_PREFIX, i)] = [value]

                    col_passwords.add(column)

        if attack_dict:
            infoMsg = "recognized possible password hashes in column%s " % ("s" if len(col_passwords) > 1 else "")
            infoMsg += "'%s'" % ", ".join(col for col in col_passwords)
            logger.info(infoMsg)

            storeHashesToFile(attack_dict)

            message = "do you want to crack them via a dictionary-based attack? %s" % ("[y/N/q]" if conf.multipleTargets else "[Y/n/q]")
            choice = readInput(message, default='N' if conf.multipleTargets else 'Y').upper()

            if choice == 'N':
                return
            elif choice == 'Q':
                raise SqlmapUserQuitException

            results = dictionaryAttack(attack_dict)
            lut = dict()

            for (_, hash_, password) in results:
                if hash_:
                    key = hash_ if hash_ not in replacements else replacements[hash_]
                    lut[key.lower()] = password
                    lut["0x%s" % key.lower()] = password

            debugMsg = "post-processing table dump"
            logger.debug(debugMsg)

            for i in xrange(count):
                for column in columns:
                    if not (column == col_user or column == '__infos__' or len(table[column]['values']) <= i):
                        value = table[column]['values'][i]

                        if value and value.lower() in lut:
                            table[column]['values'][i] = "%s (%s)" % (getUnicode(table[column]['values'][i]), getUnicode(lut[value.lower()] or HASH_EMPTY_PASSWORD_MARKER))
                            table[column]['length'] = max(table[column]['length'], len(table[column]['values'][i]))

def hashRecognition(value):
    """
    >>> hashRecognition("179ad45c6ce2cb97cf1029e212046e81") == HASH.MD5_GENERIC
    True
    >>> hashRecognition("S:2BFCFDF5895014EE9BB2B9BA067B01E0389BB5711B7B5F82B7235E9E182C") == HASH.ORACLE
    True
    >>> hashRecognition("foobar") == None
    True
    """

    retVal = None

    if value and len(value) >= 8 and ' ' not in value:   # Note: pre-filter condition (for optimization purposes)
        isOracle, isMySQL = Backend.isDbms(DBMS.ORACLE), Backend.isDbms(DBMS.MYSQL)

        if kb.cache.hashRegex is None:
            parts = []

            for name, regex in getPublicTypeMembers(HASH):
                # Hashes for Oracle and old MySQL look the same hence these checks
                if isOracle and regex == HASH.MYSQL_OLD or isMySQL and regex == HASH.ORACLE_OLD:
                    continue
                elif regex == HASH.CRYPT_GENERIC:
                    if any((value.lower() == value, value.upper() == value)):
                        continue
                else:
                    parts.append("(?P<%s>%s)" % (name, regex))

            kb.cache.hashRegex = ('|'.join(parts)).replace("(?i)", "")

        if isinstance(value, six.string_types):
            match = re.search(kb.cache.hashRegex, value, re.I)
            if match:
                algorithm, _ = [_ for _ in match.groupdict().items() if _[1] is not None][0]
                retVal = getattr(HASH, algorithm)

    return retVal

def _bruteProcessVariantA(attack_info, hash_regex, suffix, retVal, proc_id, proc_count, wordlists, custom_wordlist, api):
    if IS_WIN:
        coloramainit()

    count = 0
    rotator = 0
    hashes = set(item[0][1] for item in attack_info)

    wordlist = Wordlist(wordlists, proc_id, getattr(proc_count, "value", 0), custom_wordlist)

    try:
        for word in wordlist:
            if not attack_info:
                break

            count += 1

            if isinstance(word, six.binary_type):
                word = getUnicode(word)
            elif not isinstance(word, six.string_types):
                continue

            if suffix:
                word = word + suffix

            try:
                current = __functions__[hash_regex](password=word, uppercase=False)

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

                elif (proc_id == 0 or getattr(proc_count, "value", 0) == 1) and count % HASH_MOD_ITEM_DISPLAY == 0 or hash_regex == HASH.ORACLE_OLD or hash_regex == HASH.CRYPT_GENERIC and IS_WIN:
                    rotator += 1

                    if rotator >= len(ROTATING_CHARS):
                        rotator = 0

                    status = "current status: %s... %s" % (word.ljust(5)[:5], ROTATING_CHARS[rotator])

                    if not api:
                        dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status))

            except KeyboardInterrupt:
                raise

            except (UnicodeEncodeError, UnicodeDecodeError):
                pass  # ignore possible encoding problems caused by some words in custom dictionaries

            except Exception as ex:
                warnMsg = "there was a problem while hashing entry: %s ('%s'). " % (repr(word), getSafeExString(ex))
                warnMsg += "Please report by e-mail to '%s'" % DEV_EMAIL_ADDRESS
                logger.critical(warnMsg)

    except KeyboardInterrupt:
        pass

    finally:
        if hasattr(proc_count, "value"):
            with proc_count.get_lock():
                proc_count.value -= 1

def _bruteProcessVariantB(user, hash_, kwargs, hash_regex, suffix, retVal, found, proc_id, proc_count, wordlists, custom_wordlist, api):
    if IS_WIN:
        coloramainit()

    count = 0
    rotator = 0

    wordlist = Wordlist(wordlists, proc_id, getattr(proc_count, "value", 0), custom_wordlist)

    try:
        for word in wordlist:
            if found.value:
                break

            count += 1

            if isinstance(word, six.binary_type):
                word = getUnicode(word)
            elif not isinstance(word, six.string_types):
                continue

            if suffix:
                word = word + suffix

            try:
                current = __functions__[hash_regex](password=word, uppercase=False, **kwargs)

                if hash_ == current:
                    if hash_regex == HASH.ORACLE_OLD:  # only for cosmetic purposes
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

                elif (proc_id == 0 or getattr(proc_count, "value", 0) == 1) and count % HASH_MOD_ITEM_DISPLAY == 0:
                    rotator += 1

                    if rotator >= len(ROTATING_CHARS):
                        rotator = 0

                    status = "current status: %s... %s" % (word.ljust(5)[:5], ROTATING_CHARS[rotator])

                    if user and not user.startswith(DUMMY_USER_PREFIX):
                        status += " (user: %s)" % user

                    if not api:
                        dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status))

            except KeyboardInterrupt:
                raise

            except (UnicodeEncodeError, UnicodeDecodeError):
                pass  # ignore possible encoding problems caused by some words in custom dictionaries

            except Exception as ex:
                warnMsg = "there was a problem while hashing entry: %s ('%s'). " % (repr(word), getSafeExString(ex))
                warnMsg += "Please report by e-mail to '%s'" % DEV_EMAIL_ADDRESS
                logger.critical(warnMsg)

    except KeyboardInterrupt:
        pass

    finally:
        if hasattr(proc_count, "value"):
            with proc_count.get_lock():
                proc_count.value -= 1

def dictionaryAttack(attack_dict):
    global _multiprocessing

    suffix_list = [""]
    custom_wordlist = [""]
    hash_regexes = []
    results = []
    resumes = []
    user_hash = []
    processException = False
    foundHash = False

    if conf.disableMulti:
        _multiprocessing = None
    else:
        # Note: https://github.com/sqlmapproject/sqlmap/issues/4367
        try:
            import multiprocessing

            # problems on FreeBSD (Reference: https://web.archive.org/web/20110710041353/http://www.eggheadcafe.com/microsoft/Python/35880259/multiprocessing-on-freebsd.aspx)
            _ = multiprocessing.Queue()

            # problems with ctypes (Reference: https://github.com/sqlmapproject/sqlmap/issues/2952)
            _ = multiprocessing.Value('i')
        except (ImportError, OSError, AttributeError):
            pass
        else:
            try:
                if multiprocessing.cpu_count() > 1:
                    _multiprocessing = multiprocessing
            except NotImplementedError:
                pass

    for (_, hashes) in attack_dict.items():
        for hash_ in hashes:
            if not hash_:
                continue

            hash_ = hash_.split()[0] if hash_ and hash_.strip() else hash_
            regex = hashRecognition(hash_)

            if regex and regex not in hash_regexes:
                hash_regexes.append(regex)
                infoMsg = "using hash method '%s'" % __functions__[regex].__name__
                logger.info(infoMsg)

    for hash_regex in hash_regexes:
        keys = set()
        attack_info = []

        for (user, hashes) in attack_dict.items():
            for hash_ in hashes:
                if not hash_:
                    continue

                foundHash = True
                hash_ = hash_.split()[0] if hash_ and hash_.strip() else hash_

                if re.match(hash_regex, hash_):
                    try:
                        item = None

                        if hash_regex not in (HASH.CRYPT_GENERIC, HASH.JOOMLA, HASH.PHPASS, HASH.UNIX_MD5_CRYPT, HASH.APACHE_MD5_CRYPT, HASH.APACHE_SHA1, HASH.VBULLETIN, HASH.VBULLETIN_OLD, HASH.SSHA, HASH.SSHA256, HASH.SSHA512, HASH.DJANGO_MD5, HASH.DJANGO_SHA1, HASH.MD5_BASE64, HASH.SHA1_BASE64, HASH.SHA256_BASE64, HASH.SHA512_BASE64):
                            hash_ = hash_.lower()

                        if hash_regex in (HASH.MD5_BASE64, HASH.SHA1_BASE64, HASH.SHA256_BASE64, HASH.SHA512_BASE64):
                            item = [(user, encodeHex(decodeBase64(hash_, binary=True))), {}]
                        elif hash_regex in (HASH.MYSQL, HASH.MYSQL_OLD, HASH.MD5_GENERIC, HASH.SHA1_GENERIC, HASH.SHA224_GENERIC, HASH.SHA256_GENERIC, HASH.SHA384_GENERIC, HASH.SHA512_GENERIC, HASH.APACHE_SHA1):
                            if hash_.startswith("0x"):  # Reference: https://docs.microsoft.com/en-us/sql/t-sql/functions/hashbytes-transact-sql?view=sql-server-2017
                                hash_ = hash_[2:]
                            item = [(user, hash_), {}]
                        elif hash_regex in (HASH.SSHA,):
                            item = [(user, hash_), {"salt": decodeBase64(hash_, binary=True)[20:]}]
                        elif hash_regex in (HASH.SSHA256,):
                            item = [(user, hash_), {"salt": decodeBase64(hash_, binary=True)[32:]}]
                        elif hash_regex in (HASH.SSHA512,):
                            item = [(user, hash_), {"salt": decodeBase64(hash_, binary=True)[64:]}]
                        elif hash_regex in (HASH.ORACLE_OLD, HASH.POSTGRES):
                            item = [(user, hash_), {'username': user}]
                        elif hash_regex in (HASH.ORACLE,):
                            item = [(user, hash_), {"salt": hash_[-20:]}]
                        elif hash_regex in (HASH.MSSQL, HASH.MSSQL_OLD, HASH.MSSQL_NEW):
                            item = [(user, hash_), {"salt": hash_[6:14]}]
                        elif hash_regex in (HASH.CRYPT_GENERIC,):
                            item = [(user, hash_), {"salt": hash_[0:2]}]
                        elif hash_regex in (HASH.UNIX_MD5_CRYPT, HASH.APACHE_MD5_CRYPT):
                            item = [(user, hash_), {"salt": hash_.split('$')[2], "magic": "$%s$" % hash_.split('$')[1]}]
                        elif hash_regex in (HASH.JOOMLA, HASH.VBULLETIN, HASH.VBULLETIN_OLD):
                            item = [(user, hash_), {"salt": hash_.split(':')[-1]}]
                        elif hash_regex in (HASH.DJANGO_MD5, HASH.DJANGO_SHA1):
                            item = [(user, hash_), {"salt": hash_.split('$')[1]}]
                        elif hash_regex in (HASH.PHPASS,):
                            if ITOA64.index(hash_[3]) < 32:
                                item = [(user, hash_), {"salt": hash_[4:12], "count": 1 << ITOA64.index(hash_[3]), "prefix": hash_[:3]}]
                            else:
                                warnMsg = "invalid hash '%s'" % hash_
                                logger.warning(warnMsg)

                        if item and hash_ not in keys:
                            resumed = hashDBRetrieve(hash_)
                            if not resumed:
                                attack_info.append(item)
                                user_hash.append(item[0])
                            else:
                                infoMsg = "resuming password '%s' for hash '%s'" % (resumed, hash_)
                                if user and not user.startswith(DUMMY_USER_PREFIX):
                                    infoMsg += " for user '%s'" % user
                                logger.info(infoMsg)
                                resumes.append((user, hash_, resumed))
                            keys.add(hash_)

                    except (binascii.Error, TypeError, IndexError):
                        pass

        if not attack_info:
            continue

        if not kb.wordlists:
            while not kb.wordlists:

                # the slowest of all methods hence smaller default dict
                if hash_regex in (HASH.ORACLE_OLD, HASH.PHPASS):
                    dictPaths = [paths.SMALL_DICT]
                else:
                    dictPaths = [paths.WORDLIST]

                message = "what dictionary do you want to use?\n"
                message += "[1] default dictionary file '%s' (press Enter)\n" % dictPaths[0]
                message += "[2] custom dictionary file\n"
                message += "[3] file with list of dictionary files"
                choice = readInput(message, default='1')

                try:
                    if choice == '2':
                        message = "what's the custom dictionary's location?\n"
                        dictPath = readInput(message)
                        if dictPath:
                            dictPaths = [dictPath]
                            logger.info("using custom dictionary")
                    elif choice == '3':
                        message = "what's the list file location?\n"
                        listPath = readInput(message)
                        checkFile(listPath)
                        dictPaths = getFileItems(listPath)
                        logger.info("using custom list of dictionaries")
                    else:
                        logger.info("using default dictionary")

                    dictPaths = [_ for _ in dictPaths if _]

                    for dictPath in dictPaths:
                        checkFile(dictPath)

                        if isZipFile(dictPath):
                            _ = zipfile.ZipFile(dictPath, 'r')
                            if len(_.namelist()) == 0:
                                errMsg = "no file(s) inside '%s'" % dictPath
                                raise SqlmapDataException(errMsg)
                            else:
                                _.open(_.namelist()[0])

                    kb.wordlists = dictPaths

                except Exception as ex:
                    warnMsg = "there was a problem while loading dictionaries"
                    warnMsg += " ('%s')" % getSafeExString(ex)
                    logger.critical(warnMsg)

            message = "do you want to use common password suffixes? (slow!) [y/N] "

            if readInput(message, default='N', boolean=True):
                suffix_list += COMMON_PASSWORD_SUFFIXES

        infoMsg = "starting dictionary-based cracking (%s)" % __functions__[hash_regex].__name__
        logger.info(infoMsg)

        for item in attack_info:
            ((user, _), _) = item
            if user and not user.startswith(DUMMY_USER_PREFIX):
                custom_wordlist.append(normalizeUnicode(user))

        # Algorithms without extra arguments (e.g. salt and/or username)
        if hash_regex in (HASH.MYSQL, HASH.MYSQL_OLD, HASH.MD5_GENERIC, HASH.SHA1_GENERIC, HASH.SHA224_GENERIC, HASH.SHA256_GENERIC, HASH.SHA384_GENERIC, HASH.SHA512_GENERIC, HASH.APACHE_SHA1):
            for suffix in suffix_list:
                if not attack_info or processException:
                    break

                if suffix:
                    clearConsoleLine()
                    infoMsg = "using suffix '%s'" % suffix
                    logger.info(infoMsg)

                retVal = None
                processes = []

                try:
                    if _multiprocessing:
                        if _multiprocessing.cpu_count() > 1:
                            infoMsg = "starting %d processes " % _multiprocessing.cpu_count()
                            singleTimeLogMessage(infoMsg)

                        gc.disable()

                        retVal = _multiprocessing.Queue()
                        count = _multiprocessing.Value('i', _multiprocessing.cpu_count())

                        for i in xrange(_multiprocessing.cpu_count()):
                            process = _multiprocessing.Process(target=_bruteProcessVariantA, args=(attack_info, hash_regex, suffix, retVal, i, count, kb.wordlists, custom_wordlist, conf.api))
                            processes.append(process)

                        for process in processes:
                            process.daemon = True
                            process.start()

                        while count.value > 0:
                            time.sleep(0.5)

                    else:
                        warnMsg = "multiprocessing hash cracking is currently "
                        warnMsg += "%s on this platform" % ("not supported" if not conf.disableMulti else "disabled")
                        singleTimeWarnMessage(warnMsg)

                        retVal = _queue.Queue()
                        _bruteProcessVariantA(attack_info, hash_regex, suffix, retVal, 0, 1, kb.wordlists, custom_wordlist, conf.api)

                except KeyboardInterrupt:
                    print()
                    processException = True
                    warnMsg = "user aborted during dictionary-based attack phase (Ctrl+C was pressed)"
                    logger.warning(warnMsg)

                finally:
                    _finalize(retVal, results, processes, attack_info)

            clearConsoleLine()

        else:
            for ((user, hash_), kwargs) in attack_info:
                if processException:
                    break

                if any(_[0] == user and _[1] == hash_ for _ in results):
                    continue

                count = 0
                found = False

                for suffix in suffix_list:
                    if found or processException:
                        break

                    if suffix:
                        clearConsoleLine()
                        infoMsg = "using suffix '%s'" % suffix
                        logger.info(infoMsg)

                    retVal = None
                    processes = []

                    try:
                        if _multiprocessing:
                            if _multiprocessing.cpu_count() > 1:
                                infoMsg = "starting %d processes " % _multiprocessing.cpu_count()
                                singleTimeLogMessage(infoMsg)

                            gc.disable()

                            retVal = _multiprocessing.Queue()
                            found_ = _multiprocessing.Value('i', False)
                            count = _multiprocessing.Value('i', _multiprocessing.cpu_count())

                            for i in xrange(_multiprocessing.cpu_count()):
                                process = _multiprocessing.Process(target=_bruteProcessVariantB, args=(user, hash_, kwargs, hash_regex, suffix, retVal, found_, i, count, kb.wordlists, custom_wordlist, conf.api))
                                processes.append(process)

                            for process in processes:
                                process.daemon = True
                                process.start()

                            while count.value > 0:
                                time.sleep(0.5)

                            found = found_.value != 0

                        else:
                            warnMsg = "multiprocessing hash cracking is currently "
                            warnMsg += "%s on this platform" % ("not supported" if not conf.disableMulti else "disabled")
                            singleTimeWarnMessage(warnMsg)

                            class Value(object):
                                pass

                            retVal = _queue.Queue()
                            found_ = Value()
                            found_.value = False

                            _bruteProcessVariantB(user, hash_, kwargs, hash_regex, suffix, retVal, found_, 0, 1, kb.wordlists, custom_wordlist, conf.api)

                            found = found_.value

                    except KeyboardInterrupt:
                        print()
                        processException = True
                        warnMsg = "user aborted during dictionary-based attack phase (Ctrl+C was pressed)"
                        logger.warning(warnMsg)

                        for process in processes:
                            try:
                                process.terminate()
                                process.join()
                            except (OSError, AttributeError):
                                pass

                    finally:
                        _finalize(retVal, results, processes, attack_info)

                clearConsoleLine()

    results.extend(resumes)

    if foundHash and len(hash_regexes) == 0:
        warnMsg = "unknown hash format"
        logger.warning(warnMsg)

    if len(results) == 0:
        warnMsg = "no clear password(s) found"
        logger.warning(warnMsg)

    return results

def crackHashFile(hashFile):
    i = 0
    attack_dict = {}

    for line in getFileItems(conf.hashFile):
        if ':' in line:
            user, hash_ = line.split(':', 1)
            attack_dict[user] = [hash_]
        else:
            attack_dict["%s%d" % (DUMMY_USER_PREFIX, i)] = [line]
            i += 1

    dictionaryAttack(attack_dict)
