#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import sys

    sys.dont_write_bytecode = True

    try:
        __import__("lib.utils.versioncheck")  # this has to be the first non-standard import
    except ImportError:
        exit("[!] wrong installation detected (missing modules). Visit 'https://github.com/sqlmapproject/sqlmap/#installation' for further details")

    import bdb
    import distutils
    import glob
    import inspect
    import json
    import logging
    import os
    import re
    import shutil
    import sys
    import thread
    import threading
    import time
    import traceback
    import warnings

    warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)
    warnings.filterwarnings(action="ignore", category=DeprecationWarning)

    from lib.core.data import logger

    from lib.core.common import banner
    from lib.core.common import checkIntegrity
    from lib.core.common import createGithubIssue
    from lib.core.common import dataToStdout
    from lib.core.common import getSafeExString
    from lib.core.common import getUnicode
    from lib.core.common import maskSensitiveData
    from lib.core.common import openFile
    from lib.core.common import setPaths
    from lib.core.common import weAreFrozen
    from lib.core.data import cmdLineOptions
    from lib.core.data import conf
    from lib.core.data import kb
    from lib.core.common import unhandledExceptionMessage
    from lib.core.common import MKSTEMP_PREFIX
    from lib.core.exception import SqlmapBaseException
    from lib.core.exception import SqlmapShellQuitException
    from lib.core.exception import SqlmapSilentQuitException
    from lib.core.exception import SqlmapUserQuitException
    from lib.core.option import initOptions
    from lib.core.option import init
    from lib.core.patch import dirtyPatches
    from lib.core.settings import GIT_PAGE
    from lib.core.settings import IS_WIN
    from lib.core.settings import LEGAL_DISCLAIMER
    from lib.core.settings import THREAD_FINALIZATION_TIMEOUT
    from lib.core.settings import UNICODE_ENCODING
    from lib.core.settings import VERSION
    from lib.parse.cmdline import cmdLineParser
except KeyboardInterrupt:
    errMsg = "user aborted"

    if "logger" in globals():
        logger.critical(errMsg)
        raise SystemExit
    else:
        import time
        exit("\r[%s] [CRITICAL] %s" % (time.strftime("%X"), errMsg))

def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    try:
        _ = sys.executable if weAreFrozen() else __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)

    return getUnicode(os.path.dirname(os.path.realpath(_)), encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)

def checkEnvironment():
    try:
        os.path.isdir(modulePath())
    except UnicodeEncodeError:
        errMsg = "your system does not properly handle non-ASCII paths. "
        errMsg += "Please move the sqlmap's directory to the other location"
        logger.critical(errMsg)
        raise SystemExit

    if distutils.version.LooseVersion(VERSION) < distutils.version.LooseVersion("1.0"):
        errMsg = "your runtime environment (e.g. PYTHONPATH) is "
        errMsg += "broken. Please make sure that you are not running "
        errMsg += "newer versions of sqlmap with runtime scripts for older "
        errMsg += "versions"
        logger.critical(errMsg)
        raise SystemExit

    # Patch for pip (import) environment
    if "sqlmap.sqlmap" in sys.modules:
        for _ in ("cmdLineOptions", "conf", "kb"):
            globals()[_] = getattr(sys.modules["lib.core.data"], _)

        for _ in ("SqlmapBaseException", "SqlmapShellQuitException", "SqlmapSilentQuitException", "SqlmapUserQuitException"):
            globals()[_] = getattr(sys.modules["lib.core.exception"], _)

def main():
    """
    Main function of sqlmap when running from command line.
    """

    try:
        dirtyPatches()
        checkEnvironment()
        setPaths(modulePath())
        banner()

        # Store original command line options for possible later restoration
        cmdLineOptions.update(cmdLineParser().__dict__)
        initOptions(cmdLineOptions)

        if conf.get("api"):
            # heavy imports
            from lib.utils.api import StdDbOut
            from lib.utils.api import setRestAPILog

            # Overwrite system standard output and standard error to write
            # to an IPC database
            sys.stdout = StdDbOut(conf.taskid, messagetype="stdout")
            sys.stderr = StdDbOut(conf.taskid, messagetype="stderr")
            setRestAPILog()

        conf.showTime = True
        dataToStdout("[!] legal disclaimer: %s\n\n" % LEGAL_DISCLAIMER, forceOutput=True)
        dataToStdout("[*] starting @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        init()

        if not conf.updateAll:
            # Postponed imports (faster start)
            if conf.smokeTest:
                from lib.core.testing import smokeTest
                smokeTest()
            elif conf.liveTest:
                from lib.core.testing import liveTest
                liveTest()
            else:
                from lib.controller.controller import start
                if conf.profile:
                    from lib.core.profiling import profile
                    globals()["start"] = start
                    profile()
                else:
                    try:
                        start()
                    except thread.error as ex:
                        if "can't start new thread" in getSafeExString(ex):
                            errMsg = "unable to start new threads. Please check OS (u)limits"
                            logger.critical(errMsg)
                            raise SystemExit
                        else:
                            raise

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
            logger.critical(errMsg)
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
        valid = checkIntegrity()

        try:
            if valid is False:
                errMsg = "code integrity check failed (turning off automatic issue creation). "
                errMsg += "You should retrieve the latest development version from official GitHub "
                errMsg += "repository at '%s'" % GIT_PAGE
                logger.critical(errMsg)
                print
                dataToStdout(excMsg)
                raise SystemExit

            elif any(_ in excMsg for _ in ("tamper/", "waf/")):
                logger.critical(errMsg)
                print
                dataToStdout(excMsg)
                raise SystemExit

            elif any(_ in excMsg for _ in ("ImportError", "Can't find file for module")):
                errMsg = "invalid runtime environment ('%s')" % excMsg.split("Error: ")[-1].strip()
                logger.critical(errMsg)
                raise SystemExit

            elif "MemoryError" in excMsg:
                errMsg = "memory exhaustion detected"
                logger.critical(errMsg)
                raise SystemExit

            elif any(_ in excMsg for _ in ("No space left", "Disk quota exceeded")):
                errMsg = "no space left on output device"
                logger.critical(errMsg)
                raise SystemExit

            elif all(_ in excMsg for _ in ("No such file", "_'", "self.get_prog_name()")):
                errMsg = "corrupted installation detected ('%s'). " % excMsg.strip().split('\n')[-1]
                errMsg += "You should retrieve the latest development version from official GitHub "
                errMsg += "repository at '%s'" % GIT_PAGE
                logger.critical(errMsg)
                raise SystemExit

            elif "Read-only file system" in excMsg:
                errMsg = "output device is mounted as read-only"
                logger.critical(errMsg)
                raise SystemExit

            elif "OperationalError: disk I/O error" in excMsg:
                errMsg = "I/O error on output device"
                logger.critical(errMsg)
                raise SystemExit

            elif "Violation of BIDI" in excMsg:
                errMsg = "invalid URL (violation of Bidi IDNA rule - RFC 5893)"
                logger.critical(errMsg)
                raise SystemExit

            elif "_mkstemp_inner" in excMsg:
                errMsg = "there has been a problem while accessing temporary files"
                logger.critical(errMsg)
                raise SystemExit

            elif all(_ in excMsg for _ in ("twophase", "sqlalchemy")):
                errMsg = "please update the 'sqlalchemy' package (>= 1.1.11) "
                errMsg += "(Reference: https://qiita.com/tkprof/items/7d7b2d00df9c5f16fffe)"
                logger.critical(errMsg)
                raise SystemExit

            elif all(_ in excMsg for _ in ("scramble_caching_sha2", "TypeError")):
                errMsg = "please downgrade the 'PyMySQL' package (=< 0.8.1) "
                errMsg += "(Reference: https://github.com/PyMySQL/PyMySQL/issues/700)"
                logger.critical(errMsg)
                raise SystemExit

            elif "must be pinned buffer, not bytearray" in excMsg:
                errMsg = "error occurred at Python interpreter which "
                errMsg += "is fixed in 2.7.x. Please update accordingly "
                errMsg += "(Reference: https://bugs.python.org/issue8104)"
                logger.critical(errMsg)
                raise SystemExit

            elif "can't start new thread" in excMsg:
                errMsg = "there has been a problem while creating new thread instance. "
                errMsg += "Please make sure that you are not running too many processes"
                if not IS_WIN:
                    errMsg += " (or increase the 'ulimit -u' value)"
                logger.critical(errMsg)
                raise SystemExit

            elif "'DictObject' object has no attribute '" in excMsg and all(_ in errMsg for _ in ("(fingerprinted)", "(identified)")):
                errMsg = "there has been a problem in enumeration. "
                errMsg += "Because of a considerable chance of false-positive case "
                errMsg += "you are advised to rerun with switch '--flush-session'"
                logger.critical(errMsg)
                raise SystemExit

            elif all(_ in excMsg for _ in ("pymysql", "configparser")):
                errMsg = "wrong initialization of pymsql detected (using Python3 dependencies)"
                logger.critical(errMsg)
                raise SystemExit

            elif "bad marshal data (unknown type code)" in excMsg:
                match = re.search(r"\s*(.+)\s+ValueError", excMsg)
                errMsg = "one of your .pyc files are corrupted%s" % (" ('%s')" % match.group(1) if match else "")
                errMsg += ". Please delete .pyc files on your system to fix the problem"
                logger.critical(errMsg)
                raise SystemExit

            elif kb.get("dumpKeyboardInterrupt"):
                raise SystemExit

            elif any(_ in excMsg for _ in ("Broken pipe",)):
                raise SystemExit

            for match in re.finditer(r'File "(.+?)", line', excMsg):
                file_ = match.group(1)
                file_ = os.path.relpath(file_, os.path.dirname(__file__))
                file_ = file_.replace("\\", '/')
                if "../" in file_:
                    file_ = re.sub(r"(\.\./)+", '/', file_)
                else:
                    file_ = file_.lstrip('/')
                file_ = re.sub(r"/{2,}", '/', file_)
                excMsg = excMsg.replace(match.group(1), file_)

            errMsg = maskSensitiveData(errMsg)
            excMsg = maskSensitiveData(excMsg)

            if conf.get("api") or not valid:
                logger.critical("%s\n%s" % (errMsg, excMsg))
            else:
                logger.critical(errMsg)
                kb.stickyLevel = logging.CRITICAL
                dataToStdout(excMsg)
                createGithubIssue(errMsg, excMsg)

        except KeyboardInterrupt:
            pass

    finally:
        kb.threadContinue = False

        if conf.get("showTime"):
            dataToStdout("\n[*] ending @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        kb.threadException = True

        if kb.get("tempDir"):
            for prefix in (MKSTEMP_PREFIX.IPC, MKSTEMP_PREFIX.TESTING, MKSTEMP_PREFIX.COOKIE_JAR, MKSTEMP_PREFIX.BIG_ARRAY):
                for filepath in glob.glob(os.path.join(kb.tempDir, "%s*" % prefix)):
                    try:
                        os.remove(filepath)
                    except OSError:
                        pass
            if not filter(None, (filepath for filepath in glob.glob(os.path.join(kb.tempDir, '*')) if not any(filepath.endswith(_) for _ in ('.lock', '.exe', '_')))):
                shutil.rmtree(kb.tempDir, ignore_errors=True)

        if conf.get("hashDB"):
            try:
                conf.hashDB.flush(True)
            except KeyboardInterrupt:
                pass

        if conf.get("harFile"):
            with openFile(conf.harFile, "w+b") as f:
                json.dump(conf.httpCollector.obtain(), fp=f, indent=4, separators=(',', ': '))

        if conf.get("api"):
            try:
                conf.databaseCursor.disconnect()
            except KeyboardInterrupt:
                pass

        if conf.get("dumper"):
            conf.dumper.flush()

        # short delay for thread finalization
        try:
            _ = time.time()
            while threading.activeCount() > 1 and (time.time() - _) > THREAD_FINALIZATION_TIMEOUT:
                time.sleep(0.01)

            if cmdLineOptions.get("sqlmapShell"):
                cmdLineOptions.clear()
                conf.clear()
                kb.clear()
                conf.disableBanner = True
                main()
        except KeyboardInterrupt:
            pass
        finally:
            # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
            if threading.activeCount() > 1:
                os._exit(0)

if __name__ == "__main__":
    main()
else:
    # cancelling postponed imports (because of Travis CI checks)
    from lib.controller.controller import start
