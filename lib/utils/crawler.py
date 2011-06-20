#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import threading
import urlparse
import time

from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
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

    def getTargetUrls(self, depth=1):
        try:
            threadData = getCurrentThreadData()
            threadData.shared.outputs = oset()

            lockNames = ('limits', 'outputs', 'ioLock')
            for lock in lockNames:
                kb.locks[lock] = threading.Lock()

            def crawlThread():
                threadData = getCurrentThreadData()

                while kb.threadContinue:
                    kb.locks.limits.acquire()
                    if threadData.shared.unprocessed:
                        current = threadData.shared.unprocessed.pop()
                        kb.locks.limits.release()
                    else:
                        kb.locks.limits.release()
                        break

                    content = None
                    try:
                        if current.split('.')[-1].lower() not in CRAWL_EXCLUDE_EXTENSIONS:
                            content = Request.getPage(url=current, raise404=False)[0]
                    except sqlmapConnectionException, e:
                        errMsg = "connection exception detected (%s). skipping " % e
                        errMsg += "url '%s'" % current
                        logger.critical(errMsg)

                    if not kb.threadContinue:
                        break

                    if isinstance(content, unicode):
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

                                kb.locks.outputs.acquire()
                                threadData.shared.deeper.add(url)
                                if re.search(r"(.*?)\?(.+)", url):
                                    threadData.shared.outputs.add(url)
                                kb.locks.outputs.release()

                    if conf.verbose in (1, 2):
                        kb.locks.ioLock.acquire()
                        threadData.shared.count += 1
                        status = '%d/%d links visited (%d%s)' % (threadData.shared.count, threadData.shared.length, round(100.0*threadData.shared.count/threadData.shared.length), '%')
                        dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status), True)
                        kb.locks.ioLock.release()

            threadData.shared.deeper = set()
            threadData.shared.unprocessed = set([conf.url])

            logger.info("starting crawler")

            for i in xrange(depth):
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
            kb.suppressResumeInfo = False
