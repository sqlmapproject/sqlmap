#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import threading
import urlparse

from lib.core.common import dataToStdout
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
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

            lockNames = ('limits', 'outputs')
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

                    content = Request.getPage(url=conf.url)[0]

                    if not kb.threadContinue:
                        break

                    soup = BeautifulSoup(content)
                    for tag in soup('a'):
                        if tag.get("href"):
                            url = urlparse.urljoin(conf.url, tag.get("href"))
                            # flag to know if we are dealing with the same target host
                            target = reduce(lambda x, y: x == y, map(lambda x: urlparse.urlparse(x).netloc.split(':')[0], [url, conf.url]))
                            if target:
                                kb.locks.outputs.acquire()
                                threadData.shared.deeper.add(url)
                                if re.search(r"(.*?)\?(.+)", url):
                                    threadData.shared.outputs.add(url)
                                kb.locks.outputs.release()

            threadData.shared.deeper = set()
            threadData.shared.unprocessed = set([conf.url])

            logger.info("starting crawling")

            for i in xrange(depth):
                numThreads = min(conf.threads, len(threadData.shared.unprocessed))
                logger.debug("processing depth: %d" % i)
                runThreads(numThreads, crawlThread)
                threadData.shared.unprocessed = threadData.shared.deeper

        except KeyboardInterrupt:
            warnMsg = "user aborted during crawling. sqlmap "
            warnMsg += "will use partial list"
            logger.warn(warnMsg)

        except sqlmapConnectionException, e:
            errMsg = "connection exception detected. sqlmap "
            errMsg += "will use partial list"
            errMsg += "'%s'" % e
            logger.critical(errMsg)

        finally:
            for url in threadData.shared.outputs:
                kb.targetUrls.add(( url, None, None, None ))
            kb.suppressResumeInfo = False
