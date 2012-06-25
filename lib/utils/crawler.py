#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import httplib
import re
import urlparse
import time

from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import findPageForms
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from lib.core.settings import CRAWL_EXCLUDE_EXTENSIONS
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.request.connect import Connect as Request
from extra.beautifulsoup.beautifulsoup import BeautifulSoup
from extra.oset.pyoset import oset

class Crawler:
    """
    This class defines methods used to perform crawling (command
    line option '--crawl'
    """

    def getTargetUrls(self):
        try:
            threadData = getCurrentThreadData()
            threadData.shared.outputs = oset()

            def crawlThread():
                threadData = getCurrentThreadData()

                while kb.threadContinue:
                    with kb.locks.limits:
                        if threadData.shared.unprocessed:
                            current = threadData.shared.unprocessed.pop()
                        else:
                            break

                    content = None
                    try:
                        if current:
                            content = Request.getPage(url=current, crawling=True, raise404=False)[0]
                    except sqlmapConnectionException, e:
                        errMsg = "connection exception detected (%s). skipping " % e
                        errMsg += "url '%s'" % current
                        logger.critical(errMsg)
                    except httplib.InvalidURL, e:
                        errMsg = "invalid url detected (%s). skipping " % e
                        errMsg += "url '%s'" % current
                        logger.critical(errMsg)

                    if not kb.threadContinue:
                        break

                    if isinstance(content, unicode):
                        try:
                            soup = BeautifulSoup(content)
                            for tag in soup('a'):
                                if tag.get("href"):
                                    url = urlparse.urljoin(conf.url, tag.get("href"))

                                    # flag to know if we are dealing with the same target host
                                    target = reduce(lambda x, y: x == y, map(lambda x: urlparse.urlparse(x).netloc.split(':')[0], [url, conf.url]))

                                    if conf.scope:
                                        if not re.search(conf.scope, url, re.I):
                                            continue
                                    elif not target:
                                        continue

                                    if url.split('.')[-1].lower() not in CRAWL_EXCLUDE_EXTENSIONS:
                                        with kb.locks.outputs:
                                            threadData.shared.deeper.add(url)
                                            if re.search(r"(.*?)\?(.+)", url):
                                                threadData.shared.outputs.add(url)
                        except UnicodeEncodeError: # for non-HTML files
                            pass
                        finally:
                            if conf.forms:
                                findPageForms(content, current, False, True)

                    if conf.verbose in (1, 2):
                        threadData.shared.count += 1
                        status = '%d/%d links visited (%d%s)' % (threadData.shared.count, threadData.shared.length, round(100.0*threadData.shared.count/threadData.shared.length), '%')
                        dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status), True)

            threadData.shared.deeper = set()
            threadData.shared.unprocessed = set([conf.url])

            logger.info("starting crawler")

            for i in xrange(conf.crawlDepth):
                if i > 0 and conf.threads == 1:
                    singleTimeWarnMessage("running in a single-thread mode. This could take a while.")
                threadData.shared.count = 0
                threadData.shared.length = len(threadData.shared.unprocessed)
                numThreads = min(conf.threads, len(threadData.shared.unprocessed))
                logger.info("searching for links with depth %d" % (i + 1))
                runThreads(numThreads, crawlThread)
                clearConsoleLine(True)
                if threadData.shared.deeper:
                    threadData.shared.unprocessed = set(threadData.shared.deeper)
                else:
                    break

        except KeyboardInterrupt:
            warnMsg = "user aborted during crawling. sqlmap "
            warnMsg += "will use partial list"
            logger.warn(warnMsg)

        finally:
            clearConsoleLine(True)

            if not threadData.shared.outputs:
                warnMsg = "no usable links found (with GET parameters)"
                logger.warn(warnMsg)
            else:
                for url in threadData.shared.outputs:
                    kb.targetUrls.add(( url, None, None, None ))
