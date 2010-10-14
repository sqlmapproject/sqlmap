#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file doc/COPYING for copying permission.
"""

import codecs

from ConfigParser import NoSectionError

from lib.core.common import checkFile
from lib.core.common import UnicodeRawConfigParser
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.optiondict import optDict

config = None

def configFileProxy(section, option, boolean=False, integer=False):
    """
    Parse configuration file and save settings into the configuration
    advanced dictionary.
    """

    global config

    if config.has_option(section, option):
        if boolean:
            value = config.getboolean(section, option)
        elif integer:
            value = config.getint(section, option)
        else:
            value = config.get(section, option)

        if value:
            conf[option] = value
        else:
            conf[option] = None
    else:
        debugMsg  = "missing requested option '%s' (section " % option
        debugMsg += "'%s') into the configuration file, " % section
        debugMsg += "ignoring. Skipping to next."
        logger.debug(debugMsg)

def configFileParser(configFile):
    """
    Parse configuration file and save settings into the configuration
    advanced dictionary.
    """

    global config

    debugMsg = "parsing configuration file"
    logger.debug(debugMsg)

    checkFile(configFile)
    configFP = codecs.open(configFile, "rb", conf.dataEncoding)
    config = UnicodeRawConfigParser()
    config.readfp(configFP)

    if not config.has_section("Target"):
        raise NoSectionError, "Target in the configuration file is mandatory"

    condition  = not config.has_option("Target", "url")
    condition &= not config.has_option("Target", "list")
    condition &= not config.has_option("Target", "googleDork")

    if condition:
        errMsg  = "missing a mandatory option in the configuration "
        errMsg += "file (url, list or googleDork)"
        raise sqlmapMissingMandatoryOptionException, errMsg

    for family, optionData in optDict.items():
        for option, datatype in optionData.items():
            boolean = False
            integer = False

            if isinstance(datatype, (list, tuple, set)):
                datatype = datatype[0]

            if datatype == "boolean":
                boolean = True
            elif datatype == "integer":
                integer = True

            configFileProxy(family, option, boolean, integer)
