#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import random
import shutil
import stat
import string

from lib.core.data import logger

def purge(directory):
    """
    Safely removes content from a given directory
    """

    if not os.path.isdir(directory):
        warnMsg = "skipping purging of directory '%s' as it does not exist" % directory
        logger.warn(warnMsg)
        return

    infoMsg = "purging content of directory ('%s'). Please wait as this could take a while" % directory
    logger.info(infoMsg)

    filepaths = []
    dirpaths = []

    for rootpath, directories, filenames in os.walk(directory):
        dirpaths.extend([os.path.abspath(os.path.join(rootpath, _)) for _ in directories])
        filepaths.extend([os.path.abspath(os.path.join(rootpath, _)) for _ in filenames])

    logger.debug("changing file attributes...")
    for filepath in filepaths:
        try:
            os.chmod(filepath, stat.S_IREAD | stat.S_IWRITE)
        except:
            pass

    logger.debug("writing random data to files...")
    for filepath in filepaths:
        try:
            filesize = os.path.getsize(filepath)
            with open(filepath, 'w+b') as f:
                f.write("".join(chr(random.randint(0, 255)) for _ in xrange(filesize)))
        except:
            pass

    logger.debug("truncating files...")
    for filepath in filepaths:
        try:
            with open(filepath, 'w') as f:
                pass
        except:
            pass

    logger.debug("renaming filenames to random values...")
    for filepath in filepaths:
        try:
            os.rename(filepath, os.path.join(os.path.dirname(filepath), "".join(random.sample(string.letters, random.randint(4, 8)))))
        except:
            pass

    dirpaths.sort(cmp = lambda x, y: y.count(os.path.sep) - x.count(os.path.sep))

    logger.debug("renaming directory names to random values...")
    for dirpath in dirpaths:
        try:
            os.rename(dirpath, os.path.join(os.path.dirname(dirpath), "".join(random.sample(string.letters, random.randint(4, 8)))))
        except:
            pass

    logger.debug("deleting the whole directory tree...")
    os.chdir(os.path.join(directory, ".."))
    shutil.rmtree(directory)
