#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import sys
import time
import traceback
import warnings

warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)
warnings.filterwarnings(action="ignore", category=DeprecationWarning)

try:
    import psyco
    psyco.full()
    psyco.profile()
except ImportError:
    pass

from lib.controller.controller import start
from lib.core.common import banner
from lib.core.common import dataToStdout
from lib.core.common import getUnicode
from lib.core.common import setPaths
from lib.core.common import weAreFrozen
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.common import unhandledExceptionMessage
from lib.core.exception import exceptionsTuple
from lib.core.exception import sqlmapSilentQuitException
from lib.core.exception import sqlmapUserQuitException
from lib.core.option import init
from lib.core.profiling import profile
from lib.core.settings import LEGAL_DISCLAIMER
from lib.core.testing import smokeTest
from lib.core.testing import liveTest
from lib.parse.cmdline import cmdLineParser

def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    return os.path.dirname(getUnicode(sys.executable if weAreFrozen() else __file__, sys.getfilesystemencoding()))

def main():
    """
    Main function of sqlmap when running from command line.
    """

    try:
        paths.SQLMAP_ROOT_PATH = modulePath()
        setPaths()
        banner()

        dataToStdout("[!] legal disclaimer: %s\n\n" % LEGAL_DISCLAIMER, forceOutput=True)
        dataToStdout("[*] starting at %s\n\n" % time.strftime("%X"), forceOutput=True)

        # Store original command line options for possible later restoration
        cmdLineOptions.update(cmdLineParser().__dict__)

        init(cmdLineOptions)

        if conf.profile:
            profile()
        elif conf.smokeTest:
            smokeTest()
        elif conf.liveTest:
            liveTest()
        else:
            start()

    except sqlmapUserQuitException:
        errMsg = "user quit"
        logger.error(errMsg)

    except sqlmapSilentQuitException:
        pass

    except exceptionsTuple, e:
        e = getUnicode(e)
        logger.critical(e)

    except KeyboardInterrupt:
        print
        errMsg = "user aborted"
        logger.error(errMsg)

    except EOFError:
        print
        errMsg = "exit"
        logger.error(errMsg)

    except SystemExit:
        pass

    except:
        print
        errMsg = unhandledExceptionMessage()
        logger.critical(errMsg)
        traceback.print_exc()

    finally:
        dataToStdout("\n[*] shutting down at %s\n\n" % time.strftime("%X"), forceOutput=True)

        kb.threadContinue = False
        kb.threadException = True

        if conf.get("hashDB", None):
            try:
                conf.hashDB.flush(True)
            except KeyboardInterrupt:
                pass

        # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
        if conf.get("threads", 0) > 1 or conf.get("dnsServer", None):
            os._exit(0)
