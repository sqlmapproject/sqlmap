#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import checkFile
from lib.core.common import getSafeExString
from lib.core.common import getUnicode
from lib.core.common import openFile
from lib.core.common import unArrayizeValue
from lib.core.common import UnicodeRawConfigParser
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import OPTION_TYPE
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapSyntaxException
from lib.core.optiondict import optDict

config = None

def configFileProxy(section, option, datatype):
    """
    Parse configuration file and save settings into the configuration
    advanced dictionary.
    """

    global config

    if config.has_option(section, option):
        try:
            if datatype == OPTION_TYPE.BOOLEAN:
                value = config.getboolean(section, option) if config.get(section, option) else False
            elif datatype == OPTION_TYPE.INTEGER:
                value = config.getint(section, option) if config.get(section, option) else 0
            elif datatype == OPTION_TYPE.FLOAT:
                value = config.getfloat(section, option) if config.get(section, option) else 0.0
            else:
                value = config.get(section, option)
        except ValueError, ex:
            errMsg = "error occurred while processing the option "
            errMsg += "'%s' in provided configuration file ('%s')" % (option, getUnicode(ex))
            raise SqlmapSyntaxException(errMsg)

        if value:
            conf[option] = value
        else:
            conf[option] = None
    else:
        debugMsg = "missing requested option '%s' (section " % option
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
    configFP = openFile(configFile, "rb")

    try:
        config = UnicodeRawConfigParser()
        config.readfp(configFP)
    except Exception, ex:
        errMsg = "you have provided an invalid and/or unreadable configuration file ('%s')" % getSafeExString(ex)
        raise SqlmapSyntaxException(errMsg)

    if not config.has_section("Target"):
        errMsg = "missing a mandatory section 'Target' in the configuration file"
        raise SqlmapMissingMandatoryOptionException(errMsg)

    mandatory = False

    for option in ("direct", "url", "logFile", "bulkFile", "googleDork", "requestFile", "sitemapUrl", "wizard"):
        if config.has_option("Target", option) and config.get("Target", option) or cmdLineOptions.get(option):
            mandatory = True
            break

    if not mandatory:
        errMsg = "missing a mandatory option in the configuration file "
        errMsg += "(direct, url, logFile, bulkFile, googleDork, requestFile, sitemapUrl or wizard)"
        raise SqlmapMissingMandatoryOptionException(errMsg)

    for family, optionData in optDict.items():
        for option, datatype in optionData.items():
            datatype = unArrayizeValue(datatype)
            configFileProxy(family, option, datatype)
