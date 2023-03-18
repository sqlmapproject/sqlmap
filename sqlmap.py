#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

try:
    import sys

    sys.dont_write_bytecode = True

    try:
        __import__("lib.utils.versioncheck")  # this has to be the first non-standard import
    except ImportError:
        sys.exit(
            "[!] wrong installation detected (missing modules). Visit 'https://github.com/sqlmapproject/sqlmap/#installation' for further details")

    import bdb
    import glob
    import inspect
    import json
    import logging
    import os
    import re
    import shutil
    import sys
    import tempfile
    import threading
    import time
    import traceback
    import warnings

    if "--deprecations" not in sys.argv:
        warnings.filterwarnings(action="ignore", category=DeprecationWarning)
    else:
        warnings.resetwarnings()
        warnings.filterwarnings(action="ignore", message="'crypt'", category=DeprecationWarning)
        warnings.simplefilter("ignore", category=ImportWarning)
        if sys.version_info >= (3, 0):
            warnings.simplefilter("ignore", category=ResourceWarning)

    warnings.filterwarnings(action="ignore", message="Python 2 is no longer supported")
    warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)
    warnings.filterwarnings(action="ignore", message=".*using a very old release", category=UserWarning)
    warnings.filterwarnings(action="ignore", message=".*default buffer size will be used", category=RuntimeWarning)
    warnings.filterwarnings(action="ignore", category=UserWarning, module="psycopg2")

    from lib.core.data import logger

    from lib.core.common import banner
    from lib.core.common import checkIntegrity
    from lib.core.common import checkPipedInput
    from lib.core.common import createGithubIssue
    from lib.core.common import dataToStdout
    from lib.core.common import extractRegexResult
    from lib.core.common import filterNone
    from lib.core.common import getDaysFromLastUpdate
    from lib.core.common import getFileItems
    from lib.core.common import getSafeExString
    from lib.core.common import maskSensitiveData
    from lib.core.common import openFile
    from lib.core.common import setPaths
    from lib.core.common import weAreFrozen
    from lib.core.convert import getUnicode
    from lib.core.enums import MKSTEMP_PREFIX
    from lib.core.common import setColor
    from lib.core.common import unhandledExceptionMessage
    from lib.core.compat import LooseVersion
    from lib.core.compat import xrange
    from lib.core.data import cmdLineOptions
    from lib.core.data import conf
    from lib.core.data import kb
    from lib.core.datatype import OrderedSet
    from lib.core.exception import SqlmapBaseException
    from lib.core.exception import SqlmapShellQuitException
    from lib.core.exception import SqlmapSilentQuitException
    from lib.core.exception import SqlmapUserQuitException
    from lib.core.option import init
    from lib.core.option import initOptions
    from lib.core.patch import dirtyPatches
    from lib.core.patch import resolveCrossReferences
    from lib.core.settings import GIT_PAGE
    from lib.core.settings import IS_WIN
    from lib.core.settings import LAST_UPDATE_NAGGING_DAYS
    from lib.core.settings import LEGAL_DISCLAIMER
    from lib.core.settings import THREAD_FINALIZATION_TIMEOUT
    from lib.core.settings import UNICODE_ENCODING
    from lib.core.settings import VERSION
    from lib.parse.cmdline import cmdLineParser
    from lib.utils.crawler import crawl
except KeyboardInterrupt:
    errMsg = "user aborted"

    if "logger" in globals():
        logger.critical(errMsg)
        raise SystemExit
    else:
        import time

        sys.exit("\r[%s] [CRITICAL] %s" % (time.strftime("%X"), errMsg))


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
        Uni_errMsg = '''your system does not properly handle non-ASCII paths. \n
                    Please move the sqlmap's directory to the other location'''
        logger.critical(Uni_errMsg)
        raise SystemExit

    if LooseVersion(VERSION) < LooseVersion("1.0"):
        Loose_errMsg = '''your runtime environment (e.g. PYTHONPATH) is \n"
                    broken. Please make sure that you are not running \n"
                    newer versions of sqlmap with runtime scripts for older \n"
                    versions'''
        logger.critical(Loose_errMsg)
        raise SystemExit

    # Patch for pip (import) environment
    if "sqlmap.sqlmap" in sys.modules:
        for _ in ("cmdLineOptions", "conf", "kb"):
            globals()[_] = getattr(sys.modules["lib.core.data"], _)

        for _ in (
        "SqlmapBaseException", "SqlmapShellQuitException", "SqlmapSilentQuitException", "SqlmapUserQuitException"):
            globals()[_] = getattr(sys.modules["lib.core.exception"], _)


def main():
    """
    Main function of sqlmap when running from command line.
    """

    try:
        dirtyPatches()
        resolveCrossReferences()
        checkEnvironment()
        setPaths(modulePath())
        banner()

        # Store original command line options for possible later restoration
        args = cmdLineParser()
        cmdLineOptions.update(args.__dict__ if hasattr(args, "__dict__") else args)
        initOptions(cmdLineOptions)

        if checkPipedInput():
            conf.batch = True

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
                os._exitcode = 1 - (smokeTest() or 0)
            elif conf.vulnTest:
                from lib.core.testing import vulnTest
                os._exitcode = 1 - (vulnTest() or 0)
            else:
                from lib.controller.controller import start
                if conf.profile:
                    from lib.core.profiling import profile
                    globals()["start"] = start
                    profile()
                else:
                    try:
                        if conf.crawlDepth and conf.bulkFile:
                            targets = getFileItems(conf.bulkFile)

                            for i in xrange(len(targets)):
                                target = None

                                try:
                                    kb.targets = OrderedSet()
                                    target = targets[i]

                                    if not re.search(r"(?i)\Ahttp[s]*://", target):
                                        target = "http://%s" % target

                                    infoMsg = "starting crawler for target URL '%s' (%d/%d)" % (
                                    target, i + 1, len(targets))
                                    logger.info(infoMsg)

                                    crawl(target)
                                except Exception as ex:
                                    if target and not isinstance(ex, SqlmapUserQuitException):
                                        Quit_errMsg = "problem occurred while crawling '%s' ('%s')" % (
                                        target, getSafeExString(ex))
                                        logger.error(Quit_errMsg)
                                    else:
                                        raise
                                else:
                                    if kb.targets:
                                        start()
                        else:
                            start()
                    except Exception as ex:
                        os._exitcode = 1

                        if "can't start new thread" in getSafeExString(ex):
                            thread_errMsg = "unable to start new threads. Please check OS (u)limits"
                            logger.critical(thread_errMsg)
                            raise SystemExit
                        else:
                            raise

    except SqlmapUserQuitException:
        if not conf.batch:
            user_errMsg = "user quit"
            logger.error(user_errMsg)

    except (SqlmapSilentQuitException, bdb.BdbQuit):
        pass

    except SqlmapShellQuitException:
        cmdLineOptions.sqlmapShell = False

    except SqlmapBaseException as ex:
        base_errMsg = getSafeExString(ex)
        logger.critical(base_errMsg)

        os._exitcode = 1

        raise SystemExit

    except KeyboardInterrupt:
        try:
            print()
        except IOError:
            pass

    except EOFError:
        print()

        exit_errMsg = "exit"
        logger.error(exit_errMsg)

    except SystemExit as ex:
        os._exitcode = ex.code or 0

    except Exception as e:
        print(e)
        Exception_errmsg = unhandledExceptionMessage()
        excMsg = traceback.format_exc()
        valid = checkIntegrity()

        os._exitcode = 255

        if any(_ in excMsg for _ in ("MemoryError", "Cannot allocate memory")):
            mem_errMsg = "memory exhaustion detected"
            logger.critical(mem_errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("No space left", "Disk quota exceeded", "Disk full while accessing")):
            no_space_errMsg = "no space left on output device"
            logger.critical(no_space_errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("The paging file is too small",)):
            page_small_errMsg = "no space left for paging file"
            logger.critical(page_small_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("Access is denied", "subprocess", "metasploit")):
            no_root_errMsg = "permission error occurred while running Metasploit"
            logger.critical(no_root_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("Permission denied", "metasploit")):
            permissions_errMsg = "permission error occurred while using Metasploit"
            logger.critical(permissions_errMsg)
            raise SystemExit

        elif "Read-only file system" in excMsg:
            RO_errMsg = "output device is mounted as read-only"
            logger.critical(RO_errMsg)
            raise SystemExit

        elif "Insufficient system resources" in excMsg:
            no_ram_errMsg = "resource exhaustion detected"
            logger.critical(no_ram_errMsg)
            raise SystemExit

        elif "OperationalError: disk I/O error" in excMsg:
            IO_errMsg = "I/O error on output device"
            logger.critical(IO_errMsg)
            raise SystemExit

        elif "Violation of BIDI" in excMsg:
            BIDI_errMsg = "invalid URL (violation of Bidi IDNA rule - RFC 5893)"
            logger.critical(BIDI_errMsg)
            raise SystemExit

        elif "Invalid IPv6 URL" in excMsg:
            bad_IPv6_errMsg = "invalid URL ('%s')" % excMsg.strip().split('\n')[-1]
            logger.critical(bad_IPv6_errMsg)
            raise SystemExit

        elif "_mkstemp_inner" in excMsg:
            tmp_errMsg = "there has been a problem while accessing temporary files"
            logger.critical(tmp_errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("tempfile.mkdtemp", "tempfile.mkstemp", "tempfile.py")):
            temp_write_errMsg = '''unable to write to the temporary directory '%s'. " % tempfile.gettempdir() \n
                                Please make sure that your disk is not full and \n
                                that you have sufficient write permissions to \n
                                create temporary files and/or directories'''
            logger.critical(temp_write_errMsg)
            raise SystemExit

        elif "Permission denied: '" in excMsg:
            match = re.search(r"Permission denied: '([^']*)", excMsg)
            denied_errMsg = "permission error occurred while accessing file '%s'" % match.group(1)
            logger.critical(denied_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("twophase", "sqlalchemy")):
            update_errMsg = '''please update the 'sqlalchemy' package (>= 1.1.11) \n
                            (Reference: 'https://qiita.com/tkprof/items/7d7b2d00df9c5f16fffe')'''
            logger.critical(update_errMsg)
            raise SystemExit

        elif "invalid maximum character passed to PyUnicode_New" in excMsg and re.search(r"\A3\.[34]",
                                                                                         sys.version) is not None:
            py_version_errMsg = '''please upgrade the Python version (>= 3.5) \n
                                (Reference: 'https://bugs.python.org/issue18183')'''
            logger.critical(py_version_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("scramble_caching_sha2", "TypeError")):
            PyMySQL_errMsg = '''please downgrade the 'PyMySQL' package (=< 0.8.1) \n
                        (Reference: 'https://github.com/PyMySQL/PyMySQL/issues/700')'''
            logger.critical(PyMySQL_errMsg)
            raise SystemExit

        elif "must be pinned buffer, not bytearray" in excMsg:
            buffer_pin_errMsg = '''error occurred at Python interpreter which \n
                                is fixed in 2.7. Please update accordingly \n
                                (Reference: 'https://bugs.python.org/issue8104')'''
            logger.critical(buffer_pin_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("OSError: [Errno 22] Invalid argument: '", "importlib")):
            importlib_errMsg = "unable to read file '%s'" % extractRegexResult(
                r"OSError: \[Errno 22\] Invalid argument: '(?P<result>[^']+)", excMsg)
            logger.critical(importlib_errMsg)
            raise SystemExit

        elif "hash_randomization" in excMsg:
            hash_random_errMsg = '''error occurred at Python interpreter which \n
                                is fixed in 2.7.3. Please update accordingly \n
                                (Reference: 'https://docs.python.org/2/library/sys.html')'''
            logger.critical(hash_random_errMsg)
            raise SystemExit

        elif "AttributeError: unable to access item" in excMsg and re.search(r"3\.11\.\d+a", sys.version):
            alpha_errMsg = '''there is a known issue when sqlmap is run with ALPHA versions of Python 3.11. \n
                            Please downgrade to some stable Python version.'''
            logger.critical(alpha_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("Resource temporarily unavailable", "os.fork()", "dictionaryAttack")):
            no_dict_attack_errMsg = '''there has been a problem while running the multiprocessing hash cracking. "
                                    Please rerun with option '--threads=1' '''
            logger.critical(no_dict_attack_errMsg)
            raise SystemExit

        elif "can't start new thread" in excMsg:
            new_thread_errMsg = '''there has been a problem while creating new thread instance. \n
                                Please make sure that you are not running too many processes'''
            if not IS_WIN:
                new_thread_errMsg += " (or increase the 'ulimit -u' value)"
            logger.critical(new_thread_errMsg)
            raise SystemExit

        elif "can't allocate read lock" in excMsg:
            new_line = '\n'
            socket_errMsg = f'''there has been a problem in regular socket operation "
                                {'%s' % excMsg.strip().split(new_line)[-1]}'''
            logger.critical(socket_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("pymysql", "configparser")):
            pymsql_errMsg = "wrong initialization of 'pymsql' detected (using Python3 dependencies)"
            logger.critical(pymsql_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("ntlm", "socket.error, err", "SyntaxError")):
            python_ntlm_errMsg = "wrong initialization of 'python-ntlm' detected (using Python2 syntax)"
            logger.critical(python_ntlm_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("drda", "to_bytes")):
            drda_errMsg = "wrong initialization of 'drda' detected (using Python3 syntax)"
            logger.critical(drda_errMsg)
            raise SystemExit

        elif "'WebSocket' object has no attribute 'status'" in excMsg:
            websocket_errMsg = '''wrong websocket library detected"
                                 (Reference: 'https://github.com/sqlmapproject/sqlmap/issues/4572#issuecomment-775041086')'''
            logger.critical(websocket_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("window = tkinter.Tk()",)):
            new_line = '\n'
            GUI_errMsg = f'''there has been a problem in initialization of GUI interface \n
                            {'%s' % excMsg.strip().split(new_line)[-1]}'''
            logger.critical(GUI_errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("unable to access item 'liveTest'",)):
            livetest_errMsg = "detected usage of files from different versions of sqlmap"
            logger.critical(livetest_errMsg)
            raise SystemExit

        elif kb.get("dumpKeyboardInterrupt"):
            raise SystemExit

        elif any(_ in excMsg for _ in ("Broken pipe",)):
            raise SystemExit

        elif valid is False:
            integrity_errMsg = f'''code integrity check failed (turning off automatic issue creation). \n
                                You should retrieve the latest development version from official GitHub \n
                                repository at {'%s' % GIT_PAGE}'''
            logger.critical(integrity_errMsg)
            print()
            dataToStdout(excMsg)
            raise SystemExit

        elif any(_ in "%s\n%s" % (errMsg, excMsg) for _ in ("tamper/", "waf/", "--engagement-dojo")):
            logger.critical(errMsg)
            print()
            dataToStdout(excMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in (
        "ImportError", "ModuleNotFoundError", "<frozen", "Can't find file for module", "SAXReaderNotAvailable",
        "source code string cannot contain null bytes", "No module named", "tp_name field",
        "module 'sqlite3' has no attribute 'OperationalError'")):
            module_bad_runtime_errMsg = "invalid runtime environment ('%s')" % excMsg.split("Error: ")[-1].strip()
            logger.critical(module_bad_runtime_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("SyntaxError: Non-ASCII character", ".py on line", "but no encoding declared")):
            non_ascii_errMsg = "invalid runtime environment ('%s')" % excMsg.split("Error: ")[-1].strip()
            logger.critical(non_ascii_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("PermissionError: [WinError 5]", "multiprocessing")):
            win_error_5_errMsg = f'''there is a permission problem in running multiprocessing on this system. \n
                                    Please rerun with '--disable-multi' '''
            logger.critical(win_error_5_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("No such file", "_'")):
            new_line = '\n'
            corrupt_install_errMsg = f'''corrupted installation detected  {'%s' % excMsg.strip().split(new_line)[-1]}. \n
                                        You should retrieve the latest development version from official GitHub "
                                        repository at {'%s' % GIT_PAGE}'''
            logger.critical(corrupt_install_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("No such file", "sqlmap.conf", "Test")):
            sqlmap_conf_errMsg = "you are trying to run (hidden) development tests inside the production environment"
            logger.critical(sqlmap_conf_errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("HTTPNtlmAuthHandler", "'str' object has no attribute 'decode'")):
            HTTPNtlmAuthHandler_errMsg = '''package 'python-ntlm' has a known compatibility issue with the \n
                                            Python 3 (Reference: 'https://github.com/mullender/python-ntlm/pull/61')'''
            logger.critical(HTTPNtlmAuthHandler_errMsg)
            raise SystemExit

        elif "'DictObject' object has no attribute '" in excMsg and all(
                _ in Exception_errmsg for _ in ("(fingerprinted)", "(identified)")):
            dictobject_errMsg = '''there has been a problem in enumeration. \n
                        Because of a considerable chance of false-positive case \n
                        you are advised to rerun with switch '--flush-session' '''
            logger.critical(dictobject_errMsg)
            raise SystemExit

        elif "database disk image is malformed" in excMsg:
            bad_session_errMsg = "local session file seems to be malformed. Please rerun with '--flush-session'"
            logger.critical(bad_session_errMsg)
            raise SystemExit

        elif "AttributeError: 'module' object has no attribute 'F_GETFD'" in excMsg:
            F_GETFD_errMsg = f'''invalid runtime {'%s' % excMsg.split("Error: ")[-1].strip()} \n
                                (Reference: \n
                                'https://stackoverflow.com/a/38841364' &\n
                                'https://bugs.python.org/issue24944#msg249231')'''
            logger.critical(F_GETFD_errMsg)
            raise SystemExit

        elif "bad marshal data (unknown type code)" in excMsg:
            match = re.search(r"\s*(.+)\s+ValueError", excMsg)
            bad_marshal_errMsg = f'''one of your .pyc files are corrupted{'%s' % (" ('%s')" % match.group(1) if match else "")}. \n
                                     Please delete .pyc files on your system to fix the problem.'''
            logger.critical(bad_marshal_errMsg)
            raise SystemExit

        for match in re.finditer(r'File "(.+?)", line', excMsg):
            file_ = match.group(1)
            try:
                file_ = os.path.relpath(file_, os.path.dirname(__file__))
            except ValueError:
                pass
            file_ = file_.replace("\\", '/')
            if "../" in file_:
                file_ = re.sub(r"(\.\./)+", '/', file_)
            else:
                file_ = file_.lstrip('/')
            file_ = re.sub(r"/{2,}", '/', file_)
            excMsg = excMsg.replace(match.group(1), file_)

        api_errMsg = maskSensitiveData(errMsg)
        excMsg = maskSensitiveData(excMsg)

        if conf.get("api") or not valid:
            logger.critical("%s\n%s" % (api_errMsg, excMsg))
        else:
            logger.critical(api_errMsg)
            dataToStdout("%s\n" % setColor(excMsg.strip(), level=logging.CRITICAL))
            createGithubIssue(api_errMsg, excMsg)

    finally:
        kb.threadContinue = False

        if getDaysFromLastUpdate() > LAST_UPDATE_NAGGING_DAYS:
            warnMsg = "your sqlmap version is outdated"
            logger.warning(warnMsg)

        if conf.get("showTime"):
            dataToStdout("\n[*] ending @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        kb.threadException = True

        if kb.get("tempDir"):
            for prefix in (
            MKSTEMP_PREFIX.IPC, MKSTEMP_PREFIX.TESTING, MKSTEMP_PREFIX.COOKIE_JAR, MKSTEMP_PREFIX.BIG_ARRAY):
                for filepath in glob.glob(os.path.join(kb.tempDir, "%s*" % prefix)):
                    try:
                        os.remove(filepath)
                    except OSError:
                        pass

            if not filterNone(filepath for filepath in glob.glob(os.path.join(kb.tempDir, '*')) if not any(
                    filepath.endswith(_) for _ in (".lock", ".exe", ".so", '_'))):  # ignore junk files
                try:
                    shutil.rmtree(kb.tempDir, ignore_errors=True)
                except OSError:
                    pass

        if conf.get("hashDB"):
            conf.hashDB.flush(True)
            conf.hashDB.close()  # NOTE: because of PyPy

        if conf.get("harFile"):
            try:
                with openFile(conf.harFile, "w+b") as f:
                    json.dump(conf.httpCollector.obtain(), fp=f, indent=4, separators=(',', ': '))
            except SqlmapBaseException as ex:
                base_errMsg = getSafeExString(ex)
                logger.critical(base_errMsg)

        if conf.get("api"):
            conf.databaseCursor.disconnect()

        if conf.get("dumper"):
            conf.dumper.flush()

        # short delay for thread finalization
        _ = time.time()
        while threading.active_count() > 1 and (time.time() - _) > THREAD_FINALIZATION_TIMEOUT:
            time.sleep(0.01)

        if cmdLineOptions.get("sqlmapShell"):
            cmdLineOptions.clear()
            conf.clear()
            kb.clear()
            conf.disableBanner = True
            main()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except IOError:
        traceback.print_exc()
    finally:
        # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
        if threading.active_count() > 1:
            sys.exit(getattr(os, "_exitcode", 0))
        else:
            sys.exit(getattr(os, "_exitcode", 0))
else:
    # cancelling postponed imports (because of CI/CD checks)
    __import__("lib.controller.controller")
