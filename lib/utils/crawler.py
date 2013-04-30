#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
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
from lib.core.exception import SqlmapConnectionException
from lib.core.settings import CRAWL_EXCLUDE_EXTENSIONS
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.request.connect import Connect as Request
from thirdparty.beautifulsoup.beautifulsoup import BeautifulSoup
from thirdparty.oset.pyoset import oset

def crawl(target):
    try:
        visited = set()
        threadData = getCurrentThreadData()
        threadData.shared.value = oset()

        def crawlThread():
            threadData = getCurrentThreadData()

            while kb.threadContinue:
                with kb.locks.limit:
                    if threadData.shared.unprocessed:
                        current = threadData.shared.unprocessed.pop()
                        if current in visited:
                            continue
                        else:
                            visited.add(current)
                    else:
                        break

                content = None
                try:
                    if current:
                        content = Request.getPage(url=current, crawling=True, raise404=False)[0]
                except SqlmapConnectionException, e:
                    errMsg = "connection exception detected (%s). skipping " % e
                    errMsg += "URL '%s'" % current
                    logger.critical(errMsg)
                except httplib.InvalidURL, e:
                    errMsg = "invalid URL detected (%s). skipping " % e
                    errMsg += "URL '%s'" % current
                    logger.critical(errMsg)

                if not kb.threadContinue:
                    break

                if isinstance(content, unicode):
                    try:
                        match = re.search(r"(?si)<html[^>]*>(.+)</html>", content)
                        if match:
                            content = "<html>%s</html>" % match.group(1)

                        soup = BeautifulSoup(content)
                        tags = soup('a')

                        if not tags:
                            tags = re.finditer(r'(?si)<a[^>]+href="(?P<href>[^>"]+)"', content)

                        for tag in tags:
                            href = tag.get("href") if hasattr(tag, "get") else tag.group("href")

                            if href:
                                if threadData.lastRedirectURL and threadData.lastRedirectURL[0] == threadData.lastRequestUID:
                                    current = threadData.lastRedirectURL[1]
                                url = urlparse.urljoin(current, href)

                                # flag to know if we are dealing with the same target host
                                _ = reduce(lambda x, y: x == y, map(lambda x: urlparse.urlparse(x).netloc.split(':')[0], (url, target)))

                                if conf.scope:
                                    if not re.search(conf.scope, url, re.I):
                                        continue
                                elif not _:
                                    continue

                                if url.split('.')[-1].lower() not in CRAWL_EXCLUDE_EXTENSIONS:
                                    with kb.locks.value:
                                        threadData.shared.deeper.add(url)
                                        if re.search(r"(.*?)\?(.+)", url):
                                            threadData.shared.value.add(url)
                    except UnicodeEncodeError:  # for non-HTML files
                        pass
                    finally:
                        if conf.forms:
                            findPageForms(content, current, False, True)

                if conf.verbose in (1, 2):
                    threadData.shared.count += 1
                    status = '%d/%d links visited (%d%%)' % (threadData.shared.count, threadData.shared.length, round(100.0 * threadData.shared.count / threadData.shared.length))
                    dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status), True)

        threadData.shared.deeper = set()
        threadData.shared.unprocessed = set([target])

        infoMsg = "starting crawler"
        if conf.bulkFile:
            infoMsg += " for target URL '%s'" % target
        logger.info(infoMsg)

        for i in xrange(conf.crawlDepth):
            if i > 0 and conf.threads == 1:
                singleTimeWarnMessage("running in a single-thread mode. This could take a while")

            threadData.shared.count = 0
            threadData.shared.length = len(threadData.shared.unprocessed)
            numThreads = min(conf.threads, len(threadData.shared.unprocessed))

            if not conf.bulkFile:
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

        if not threadData.shared.value:
            warnMsg = "no usable links found (with GET parameters)"
            logger.warn(warnMsg)
        else:
            for url in threadData.shared.value:
                kb.targets.add((url, None, None, None))
