#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import bdb
import inspect
import logging
import os
import re
import shutil
import sys
import time
import traceback
import warnings

warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)
warnings.filterwarnings(action="ignore", category=DeprecationWarning)

from lib.utils import versioncheck  # this has to be the first non-standard import

from lib.controller.controller import start
from lib.core.common import banner
from lib.core.common import createGithubIssue
from lib.core.common import dataToStdout
from lib.core.common import getSafeExString
from lib.core.common import getUnicode
from lib.core.common import maskSensitiveData
from lib.core.common import setPaths
from lib.core.common import weAreFrozen
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.common import unhandledExceptionMessage
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapShellQuitException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapUserQuitException
from lib.core.option import initOptions
from lib.core.option import init
from lib.core.profiling import profile
from lib.core.settings import LEGAL_DISCLAIMER
from lib.core.testing import smokeTest
from lib.core.testing import liveTest
from lib.parse.cmdline import cmdLineParser
from lib.utils.api import setRestAPILog
from lib.utils.api import StdDbOut

def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    try:
        _ = sys.executable if weAreFrozen() else __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)

    return getUnicode(os.path.dirname(os.path.realpath(_)), encoding=sys.getfilesystemencoding())

def main():
    """
    Main function of sqlmap when running from command line.
    """

    try:
        paths.SQLMAP_ROOT_PATH = modulePath()

        try:
            os.path.isdir(paths.SQLMAP_ROOT_PATH)
        except UnicodeEncodeError:
            errMsg = "your system does not properly handle non-ASCII paths. "
            errMsg += "Please move the sqlmap's directory to the other location"
            logger.error(errMsg)
            raise SystemExit

        setPaths()

        # Store original command line options for possible later restoration
        cmdLineOptions.update(cmdLineParser().__dict__)
        initOptions(cmdLineOptions)

        if hasattr(conf, "api"):
            # Overwrite system standard output and standard error to write
            # to an IPC database
            sys.stdout = StdDbOut(conf.taskid, messagetype="stdout")
            sys.stderr = StdDbOut(conf.taskid, messagetype="stderr")
            setRestAPILog()

        banner()

        conf.showTime = True
        dataToStdout("[!] legal disclaimer: %s\n\n" % LEGAL_DISCLAIMER, forceOutput=True)
        dataToStdout("[*] starting at %s\n\n" % time.strftime("%X"), forceOutput=True)

        init()

        if conf.profile:
            profile()
        elif conf.smokeTest:
            smokeTest()
        elif conf.liveTest:
            liveTest()
        else:
            start()

    except SqlmapUserQuitException:
        errMsg = "user quit"
        try:
            logger.error(errMsg)
        except KeyboardInterrupt:
            pass

    except (SqlmapSilentQuitException, bdb.BdbQuit):
        pass

    except SqlmapShellQuitException:
        cmdLineOptions.sqlmapShell = False

    except SqlmapBaseException as ex:
        errMsg = getSafeExString(ex)
        try:
            logger.critical(errMsg)
        except KeyboardInterrupt:
            pass

        raise SystemExit

    except KeyboardInterrupt:
        print

        errMsg = "user aborted"
        try:
            logger.error(errMsg)
        except KeyboardInterrupt:
            pass

    except EOFError:
        print
        errMsg = "exit"

        try:
            logger.error(errMsg)
        except KeyboardInterrupt:
            pass

    except SystemExit:
        pass

    except:
        print
        errMsg = unhandledExceptionMessage()
        excMsg = traceback.format_exc()

        try:
            if any(_ in excMsg for _ in ("No space left", "Disk quota exceeded")):
                errMsg = "no space left on output device"
                logger.error(errMsg)
                raise SystemExit

            elif "bad marshal data (unknown type code)" in excMsg:
                match = re.search(r"\s*(.+)\s+ValueError", excMsg)
                errMsg = "one of your .pyc files are corrupted%s" % (" ('%s')" % match.group(1) if match else "")
                errMsg += ". Please delete .pyc files on your system to fix the problem"
                logger.error(errMsg)
                raise SystemExit

            for match in re.finditer(r'File "(.+?)", line', excMsg):
                file_ = match.group(1)
                file_ = os.path.relpath(file_, os.path.dirname(__file__))
                file_ = file_.replace("\\", '/')
                file_ = re.sub(r"\.\./", '/', file_).lstrip('/')
                excMsg = excMsg.replace(match.group(1), file_)

            errMsg = maskSensitiveData(errMsg)
            excMsg = maskSensitiveData(excMsg)

            logger.critical(errMsg)
            kb.stickyLevel = logging.CRITICAL
            dataToStdout(excMsg)
            createGithubIssue(errMsg, excMsg)
        except KeyboardInterrupt:
            pass

    finally:
        kb.threadContinue = False
        kb.threadException = True

        if conf.get("showTime"):
            dataToStdout("\n[*] shutting down at %s\n\n" % time.strftime("%X"), forceOutput=True)

        if kb.get("tempDir"):
            shutil.rmtree(kb.tempDir, ignore_errors=True)

        if conf.get("hashDB"):
            try:
                conf.hashDB.flush(True)
            except KeyboardInterrupt:
                pass

        if cmdLineOptions.get("sqlmapShell"):
            cmdLineOptions.clear()
            conf.clear()
            kb.clear()
            main()

        if hasattr(conf, "api"):
            try:
                conf.database_cursor.disconnect()
            except KeyboardInterrupt:
                pass

        if conf.get("dumper"):
            conf.dumper.flush()

        # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
        if conf.get("threads", 0) > 1 or conf.get("dnsServer"):
            os._exit(0)

if __name__ == "__main__":
    main()
