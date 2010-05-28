#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

import os
import sys
import time
import traceback
import warnings

warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)

try:
    import psyco
    psyco.full()
    psyco.profile()
except ImportError, _:
    pass

from lib.controller.controller import start
from lib.core.common import banner
from lib.core.common import profile
from lib.core.common import setPaths
from lib.core.common import weAreFrozen
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import exceptionsTuple
from lib.core.exception import unhandledException
from lib.core.option import init
from lib.parse.cmdline import cmdLineParser

def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    if weAreFrozen():
        return os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding()))
    else:
        return os.path.dirname(os.path.realpath(__file__))

def main():
    """
    Main function of sqlmap when running from command line.
    """

    paths.SQLMAP_ROOT_PATH = modulePath()
    setPaths()

    banner()
    cmdLineOptions = cmdLineParser()

    print "[*] starting at: %s\n" % time.strftime("%X")

    try:
        init(cmdLineOptions)
        if conf.profile:
            profile()
        else:
            start()
    except exceptionsTuple, e:
        e = unicode(e)
        logger.error(e)

    except KeyboardInterrupt:
        print
        errMsg = "user aborted"
        logger.error(errMsg)

    except EOFError:
        print
        errMsg = "exit"
        logger.error(errMsg)

    except:
        print
        errMsg = unhandledException()
        logger.error(errMsg)
        traceback.print_exc()

    print "\n[*] shutting down at: %s\n" % time.strftime("%X")

if __name__ == "__main__":
    main()
