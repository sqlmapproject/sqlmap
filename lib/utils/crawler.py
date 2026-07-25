#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import bisect
import json
import os
import re
import tempfile
import time

from itertools import islice

from lib.core.common import checkSameHost
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import findPageForms
from lib.core.common import getSafeExString
from lib.core.common import openFile
from lib.core.common import readInput
from lib.core.common import safeCSValue
from lib.core.common import urldecode
from lib.core.compat import xrange
from lib.core.convert import htmlUnescape
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import OrderedSet
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapSyntaxException
from lib.core.settings import CRAWL_EXCLUDE_EXTENSIONS
from lib.core.settings import JAVASCRIPT_ENDPOINT_REGEX
from lib.core.settings import MAX_JAVASCRIPT_ENDPOINTS
from lib.core.settings import MAX_JAVASCRIPT_FOLD_DISTANCE
from lib.core.settings import MAX_JAVASCRIPT_MINE_SIZE
from lib.core.settings import MAX_ROBOTS_ENTRIES
from lib.core.settings import WELL_KNOWN_ENDPOINT_PATHS
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.parse.sitemap import parseSitemap
from lib.request.connect import Connect as Request
from thirdparty import six
from thirdparty.beautifulsoup.beautifulsoup import BeautifulSoup
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import urllib as _urllib

def _inScope(url, target):
    """Single predicate governing every crawler request/result: honor --scope if set, else same-host."""

    return (re.search(conf.scope, url, re.I) is not None) if conf.scope else checkSameHost(url, target)

def _mineJavaScript(content, base):
    """Extract candidate API endpoints referenced inside a JavaScript bundle - the fetch/axios/XHR
    targets and absolute-path string literals that power single-page apps and are invisible to
    href/src scraping. Returns [(absoluteURL, parametrized), ...] (capped, static assets dropped);
    'parametrized' marks a path templated with a dynamic segment (e.g. `/user/${id}` -> `/user/1`)
    or carrying a query string, i.e. a directly testable target rather than a page merely to crawl.

    Light constant folding resolves the common `var base="/api"; fetch(base+"/users")` idiom that
    plain literal scraping would split into two useless halves.

    >>> r = _mineJavaScript('fetch("/api/users?id=1");x="/img/logo.png";t=`/user/${i}/x`', "http://h/a.js")
    >>> ("http://h/api/users?id=1", True) in r and ("http://h/user/1/x", False) in r   # query -> target, template -> crawl only
    True
    >>> any(_.endswith("logo.png") for _, __ in r)
    False
    >>> r = _mineJavaScript('var base="/api/v1";fetch(base+"/users")', "http://h/a.js")
    >>> ("http://h/api/v1/users", False) in r          # folded ...
    True
    >>> any(_ == "http://h/users" for _, __ in r)      # ... and only THIS folded suffix occurrence is dropped
    False
    """

    content = content[:MAX_JAVASCRIPT_MINE_SIZE]           # endpoints live near the top; bound the work on a hostile bundle
    _template = r"\$\{[^}]*\}|:[A-Za-z_]\w*|\{[A-Za-z_.]+\}|<[A-Za-z_]\w*>"

    # index path/URL-valued string constants by name (positions ascending) so a `<name> + "/suffix"`
    # concatenation resolves against the NEAREST PRECEDING assignment via binary search - minified bundles
    # reuse identifiers (a global last-wins map would fold the wrong value) and can hold tens of thousands
    # of assignments (a linear scan per concatenation would be quadratic)
    byName = {}
    for match in re.finditer(r"""(?:\b(?:var|let|const)\s+|[,{(]\s*)(?P<name>\w+)\s*[:=]\s*["'`](?P<value>(?:https?:)?/[^"'`\s]{0,256})["'`]""", content):
        byName.setdefault(match.group("name"), ([], []))
        byName[match.group("name")][0].append(match.start())
        byName[match.group("name")][1].append(match.group("value"))

    candidates = []                                        # (spanStart, text): spanStart correlates a folded suffix to the literal it consumes
    for match in re.finditer(r"""(?P<name>\w+)\s*\+\s*["'`](?P<suffix>/[^"'`\s]{0,256})["'`]""", content):
        entry = byName.get(match.group("name"))
        if entry:
            index = bisect.bisect_left(entry[0], match.start()) - 1
            # best-effort, deliberately not a JS parser: fold only against a NEARBY preceding assignment so a
            # far-away or differently-scoped `var base=...` (e.g. inside another function) is not mis-applied
            if index >= 0 and match.start() - entry[0][index] <= MAX_JAVASCRIPT_FOLD_DISTANCE:
                candidates.append((match.start("suffix"), entry[1][index].rstrip("/") + match.group("suffix")))
    folded = set(_[0] for _ in candidates)                 # exact source spans consumed by folding
    for match in re.finditer(JAVASCRIPT_ENDPOINT_REGEX, content):
        if match.start("result") not in folded:            # suppress only THIS occurrence, not every same-text literal
            candidates.append((match.start("result"), match.group("result")))

    candidates.sort(key=lambda _: _[0])                    # process in source order so the endpoint cap keeps the earliest, not every folded one first

    results = []
    seen = set()
    for _, candidate in candidates:
        if any(_ in candidate for _ in ("\\", "^", "*", " ")):     # regex/glob fragments, not endpoints
            continue
        candidate = re.sub(_template, "1", candidate)              # concrete, crawlable path segment
        url = _urllib.parse.urljoin(base, candidate)
        if not re.search(r"(?i)\Ahttps?://[^/]+/", url):          # must resolve to an absolute http(s) URL
            continue
        if (extractRegexResult(r"\A[^?#]+\.(?P<result>\w+)([?#]|\Z)", url) or "").lower() in CRAWL_EXCLUDE_EXTENSIONS:
            continue
        # only a real query parameter makes a URL a directly testable target; a path with a (substituted)
        # dynamic segment is crawled, not marked, because sqlmap's URI injection needs the '*' marker at the
        # right segment (a middle template like /user/1/x would otherwise be mis-tested at its end)
        isTarget = re.search(r"\?.*\b\w+=", url) is not None
        if url not in seen:
            seen.add(url)
            results.append((url, isTarget))
            if len(results) >= MAX_JAVASCRIPT_ENDPOINTS:
                break

    return results

def _sourceMapEndpoints(mapContent, base):
    """A '//# sourceMappingURL=' map ships the original, un-minified sources in 'sourcesContent';
    mining those recovers endpoints (and pre-minification structure) that the bundle alone hides -
    a trick commercial crawlers (Burp, Acunetix) lean on. Returns the same shape as _mineJavaScript."""

    if len(mapContent) > 8 * MAX_JAVASCRIPT_MINE_SIZE:     # do not json-parse an oversized (hostile) map into RAM
        return []
    try:
        data = json.loads(mapContent)
    except ValueError:
        return []
    sources = data.get("sourcesContent") if isinstance(data, dict) else None
    if not isinstance(sources, (list, tuple)):             # a valid JSON map may carry a non-array here
        return []
    parts = []
    size = 0
    for source in sources:                                 # join a bounded slice (avoid repeated string realloc)
        if isinstance(source, six.text_type):
            parts.append(source[:MAX_JAVASCRIPT_MINE_SIZE - size])
            size += len(parts[-1])
            if size >= MAX_JAVASCRIPT_MINE_SIZE:
                break
    return _mineJavaScript("\n".join(parts), base) if parts else []

def crawl(target, post=None, cookie=None):
    if not target:
        return

    try:
        visited = set()
        threadData = getCurrentThreadData()
        threadData.shared.value = OrderedSet()
        threadData.shared.formsFound = False
        # host-level recon (robots/well-known/sitemap) runs on this thread and carries the session cookie;
        # confine its redirects to scope (reset in 'finally' so later requests on this thread are unaffected)
        threadData.crawlRedirectFilter = lambda url: _inScope(url, target)

        def crawlThread():
            threadData = getCurrentThreadData()
            # confine this worker's redirects (e.g. a source-map fetch) to scope; reset in 'finally' so a pooled
            # thread later reused for injection is not left restricted to the crawl scope
            threadData.crawlRedirectFilter = lambda url: _inScope(url, target)

            try:
                _crawlThreadLoop(threadData)
            finally:
                threadData.crawlRedirectFilter = None

        def _crawlThreadLoop(threadData):
            def consume(endpoints):
                # feed mined endpoints through the same scope-check + deeper/value flow as scraped links
                for url, isTarget in endpoints:
                    if not _inScope(url, target):
                        continue
                    with kb.locks.value:
                        threadData.shared.deeper.add(url)
                        if isTarget:
                            threadData.shared.value.add(url)

            while kb.threadContinue:
                with kb.locks.limit:
                    if threadData.shared.unprocessed:
                        current = threadData.shared.unprocessed.pop()
                        if current in visited:
                            continue
                        elif conf.crawlExclude and re.search(conf.crawlExclude, current):
                            dbgMsg = "skipping '%s'" % current
                            logger.debug(dbgMsg)
                            continue
                        else:
                            visited.add(current)
                    else:
                        break

                content = None
                try:
                    if current:
                        content = Request.getPage(url=current, post=post, cookie=None, crawling=True, raise404=False)[0]
                except SqlmapConnectionException as ex:
                    errMsg = "connection exception detected ('%s'). skipping " % getSafeExString(ex)
                    errMsg += "URL '%s'" % current
                    logger.critical(errMsg)
                except SqlmapSyntaxException:
                    errMsg = "invalid URL detected. skipping '%s'" % current
                    logger.critical(errMsg)
                except _http_client.InvalidURL as ex:
                    errMsg = "invalid URL detected ('%s'). skipping " % getSafeExString(ex)
                    errMsg += "URL '%s'" % current
                    logger.critical(errMsg)

                if not kb.threadContinue:
                    break

                if isinstance(content, six.text_type) and (current or "").split("?", 1)[0].lower().endswith((".js", ".mjs")):
                    try:
                        consume(_mineJavaScript(content, current))
                        # follow a source map ('//# sourceMappingURL=') to the original un-minified sources;
                        # the URL is attacker-controlled, so it must stay same-host/in-scope (no SSRF) and be
                        # fetched at most once
                        smatch = re.search(r"(?m)[#@]\s*sourceMappingURL\s*=\s*(?P<url>[^\s'\"]+)", content)
                        if smatch and not smatch.group("url").startswith("data:"):
                            mapURL = _urllib.parse.urljoin(current, smatch.group("url"))
                            with kb.locks.value:
                                fetch = mapURL.startswith(("http://", "https://")) and _inScope(mapURL, target) and mapURL not in visited
                                if fetch:
                                    visited.add(mapURL)
                            if fetch:                       # GET the static map (not a re-POST) and keep the auth cookie
                                mapContent = Request.getPage(url=mapURL, post=None, cookie=cookie, crawling=True, raise404=False)[0]
                                # a same-host map that redirected off-scope must not have its (authenticated) body used
                                redirected = threadData.lastRedirectURL[1] if (threadData.lastRedirectURL and threadData.lastRedirectURL[0] == threadData.lastRequestUID) else None
                                if isinstance(mapContent, six.text_type) and (redirected is None or _inScope(redirected, target)):
                                    consume(_sourceMapEndpoints(mapContent, current))
                    except (ValueError, SqlmapConnectionException):
                        pass
                elif isinstance(content, six.text_type) and content[:64].lstrip()[:1] in ("{", "["):
                    try:                                    # a JSON API response: mine embedded resource links (REST/HATEOAS, pagination)
                        consume(_mineJavaScript(content, current))
                    except ValueError:
                        pass
                elif isinstance(content, six.text_type):
                    # base for resolving links AND forms: the redirect target (if any), refined by <base href>
                    # below; defined before the try so the 'finally' can rely on it even if parsing fails
                    linkBase = current
                    if threadData.lastRedirectURL and threadData.lastRedirectURL[0] == threadData.lastRequestUID:
                        linkBase = threadData.lastRedirectURL[1]
                    try:
                        match = re.search(r"(?si)<html[^>]*>(.+)</html>", content)
                        if match:
                            content = "<html>%s</html>" % match.group(1)

                        soup = BeautifulSoup(content)
                        tags = soup('a')

                        tags += re.finditer(r'(?i)\s(href|src)=["\'](?P<href>[^>"\']+)', content)
                        tags += re.finditer(r'(?i)window\.open\(["\'](?P<href>[^)"\']+)["\']', content)
                        # URL-bearing data-* attributes and navigational sinks that mature crawlers also follow.
                        # Note: <form action>/formaction are intentionally NOT scraped here - they need method +
                        # field semantics (handled by --forms/findPageForms), and data-action usually holds a
                        # command name, not a URL
                        tags += re.finditer(r'(?i)\s(?:data-(?:url|href|src|link|api|endpoint))=["\'](?P<href>[^>"\']+)', content)
                        tags += re.finditer(r'(?i)<meta[^>]+?http-equiv=["\']?refresh\b[^>]+?url=(?P<href>[^"\'>\s;]+)', content)
                        tags += re.finditer(r'(?i)<object\b[^>]*?\sdata=["\'](?P<href>[^>"\']+)', content)

                        # honor <base href> for correct relative-URL resolution, but only if it stays in scope -
                        # a cross-origin <base> must not become the resolution base for links or (via linkBase) forms
                        baseTag = re.search(r'(?i)<base[^>]+?href=["\'](?P<href>[^"\'>]+)', content)
                        if baseTag:
                            rebased = _urllib.parse.urljoin(linkBase, htmlUnescape(baseTag.group("href")))
                            if (re.search(conf.scope, rebased, re.I) if conf.scope else checkSameHost(rebased, target)):
                                linkBase = rebased

                        for tag in tags:
                            href = tag.get("href") if hasattr(tag, "get") else tag.group("href")

                            if href:
                                url = _urllib.parse.urldefrag(_urllib.parse.urljoin(linkBase, htmlUnescape(href)))[0]

                                if not _inScope(url, target):
                                    continue

                                extension = (extractRegexResult(r"\A[^?#]+\.(?P<result>\w+)([?#]|\Z)", url) or "").lower()
                                if extension in ("js", "mjs"):
                                    with kb.locks.value:            # enqueue the bundle so its endpoints get mined
                                        threadData.shared.deeper.add(url)
                                elif extension not in CRAWL_EXCLUDE_EXTENSIONS:
                                    with kb.locks.value:
                                        threadData.shared.deeper.add(url)
                                        if re.search(r"(.*?)\?(.+)", url) and not re.search(r"\?(v=)?\d+\Z", url) and not re.search(r"(?i)\.(m?js|css)(\?|\Z)", url):
                                            threadData.shared.value.add(url)

                        # inline <script> blocks (no external src), including SPA hydration state such as
                        # __NEXT_DATA__ / __NUXT__ / window.__INITIAL_STATE__, carry API URLs and fetch calls;
                        # concatenate under one page-wide byte budget so a page of many tiny scripts cannot
                        # multiply past the per-mine endpoint cap
                        inline = []
                        inlineSize = 0
                        for script in re.finditer(r"(?is)<script(?![^>]*\bsrc\s*=)[^>]*>(.+?)</script>", content):
                            body = script.group(1)[:MAX_JAVASCRIPT_MINE_SIZE - inlineSize]
                            inline.append(body)
                            inlineSize += len(body)
                            if inlineSize >= MAX_JAVASCRIPT_MINE_SIZE:
                                break
                        if inline:
                            consume(_mineJavaScript("\n".join(inline), linkBase))
                    except UnicodeEncodeError:  # for non-HTML files
                        pass
                    except ValueError:          # for non-valid links
                        pass
                    except AssertionError:      # for invalid HTML
                        pass
                    finally:
                        if conf.forms:
                            threadData.shared.formsFound |= len(findPageForms(content, linkBase, False, True)) > 0

                if conf.verbose in (1, 2):
                    threadData.shared.count += 1
                    status = '%d/%d links visited (%d%%)' % (threadData.shared.count, threadData.shared.length, round(100.0 * threadData.shared.count / threadData.shared.length))
                    dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status), True)

        threadData.shared.deeper = set()
        threadData.shared.unprocessed = set([target])

        _ = re.sub(r"(?<!/)/(?!/).*", "", target)
        if _:
            if target.strip('/') != _.strip('/'):
                threadData.shared.unprocessed.add(_)

        if re.search(r"\?.*\b\w+=", target):
            threadData.shared.value.add(target)

        # host-level recon (robots.txt + well-known endpoint directories) is done at most once per host so a
        # multi-target run does not re-probe (and re-404) the same host over and over
        _split = _urllib.parse.urlsplit(target)
        crawlHost = ("%s://%s" % (_split.scheme, _split.netloc)).lower()   # scheme+netloc dedup key (finer than the host-level scope predicate on purpose - never re-probe the same origin)
        with kb.locks.value:                                              # atomic check-and-claim so concurrent target crawls do not double-probe a host
            reconHost = bool(_split.netloc) and crawlHost not in kb.crawledHosts
            if reconHost:
                kb.crawledHosts.add(crawlHost)

        # every sitemap source (robots.txt 'Sitemap:' lines AND the /sitemap.xml guess below) shares ONE fetch/URL
        # budget and ONE visited set, so a hostile robots.txt advertising many roots cannot multiply the per-root
        # limits into ~100k fetches, and a sitemap listed twice is fetched once
        sitemapItems = OrderedSet()
        sitemapVisited = set()

        # robots.txt Disallow/Allow entries expose unlinked paths (admin panels, API roots) that crawlers
        # (Burp, Acunetix) routinely harvest as seeds; the file itself must be in scope before it is fetched
        robotsUrl = _urllib.parse.urljoin(target, "/robots.txt")
        try:
            robots = Request.getPage(url=robotsUrl, post=None, cookie=cookie, crawling=True, raise404=False)[0] if (reconHost and _inScope(robotsUrl, target)) else None
        except Exception:
            robots = None
        if isinstance(robots, six.text_type):
            # ONE combined budget across Disallow/Allow and Sitemap lines, consumed lazily (islice over finditer)
            # so a huge/repetitive robots.txt is neither fully materialized nor over-processed
            remaining = MAX_ROBOTS_ENTRIES
            for match in islice(re.finditer(r"(?im)^\s*(?:dis)?allow\s*:\s*(/\S*)", robots), remaining):
                remaining -= 1
                path = match.group(1)
                if any(_ in path for _ in "*$"):                  # a pattern, not a concrete path
                    continue
                url = _urllib.parse.urljoin(target, path)
                if _inScope(url, target) and (extractRegexResult(r"\A[^?#]+\.(?P<result>\w+)([?#]|\Z)", url) or "").lower() not in CRAWL_EXCLUDE_EXTENSIONS:
                    threadData.shared.unprocessed.add(url)
                    if re.search(r"\?.*\b\w+=", url):
                        threadData.shared.value.add(url)

            # follow the sitemaps robots.txt advertises into the SHARED budget/visited; the advertised URL AND every
            # nested sitemap parseSitemap fetches recursively must pass the same scope predicate (enforced inside)
            for match in islice(re.finditer(r"(?im)^\s*sitemap\s*:\s*(https?://\S+)", robots), max(remaining, 0)):
                sitemapUrl = match.group(1)
                if not _inScope(sitemapUrl, target):
                    continue
                try:
                    parseSitemap(sitemapUrl, retVal=sitemapItems, visited=sitemapVisited, urlFilter=lambda _: _inScope(_, target))
                except Exception:
                    pass

        # heuristic path discovery from self-describing JSON documents (OIDC discovery, OpenAPI/Swagger).
        # this mines endpoint-looking strings, NOT a full OpenAPI model - basePath/servers are not merged and
        # $ref/examples are not resolved; '--openapi' does exact API enumeration
        for path in (WELL_KNOWN_ENDPOINT_PATHS if reconHost else ()):
            probe = _urllib.parse.urljoin(target, path)
            if probe in visited or not _inScope(probe, target):
                continue
            visited.add(probe)
            try:
                blob = Request.getPage(url=probe, post=None, cookie=cookie, crawling=True, raise404=False)[0]
            except Exception:
                blob = None
            if isinstance(blob, six.text_type) and blob[:64].lstrip()[:1] in ("{", "["):
                for url, isTarget in _mineJavaScript(blob, probe):
                    if _inScope(url, target):
                        threadData.shared.unprocessed.add(url)
                        if isTarget:
                            threadData.shared.value.add(url)

        if kb.checkSitemap is None:
            message = "do you want to check for the existence of "
            message += "site's sitemap(.xml) [y/N] "
            kb.checkSitemap = readInput(message, default='N', boolean=True)

        url = _urllib.parse.urljoin(target, "/sitemap.xml")
        if kb.checkSitemap and _inScope(url, target):
            try:                                                  # into the same shared budget/visited as the robots sitemaps
                parseSitemap(url, retVal=sitemapItems, visited=sitemapVisited, urlFilter=lambda _: _inScope(_, target))
            except SqlmapConnectionException as ex:
                if "page not found" in getSafeExString(ex):
                    logger.warning("'sitemap.xml' not found")
            except:
                pass

        # single consumption of every sitemap-derived URL (already scope-filtered inside parseSitemap): a URL with
        # GET parameters is a target, and - at depth > 1 - all are queued for further crawling
        if sitemapItems:
            for item in sitemapItems:
                if re.search(r"\?.*\b\w+=", item):
                    threadData.shared.value.add(item)
                if conf.crawlDepth > 1:
                    threadData.shared.unprocessed.add(item)
            logger.info("%d link(s) found via sitemap(s)" % len(sitemapItems))

        if not conf.bulkFile:
            infoMsg = "starting crawler for target URL '%s'" % target
            logger.info(infoMsg)

        for i in xrange(conf.crawlDepth):
            threadData.shared.count = 0
            threadData.shared.length = len(threadData.shared.unprocessed)
            numThreads = min(conf.threads, len(threadData.shared.unprocessed))

            if not conf.bulkFile:
                logger.info("searching for links with depth %d" % (i + 1))

            runThreads(numThreads, crawlThread, threadChoice=(i > 0))
            clearConsoleLine(True)

            if threadData.shared.deeper:
                threadData.shared.unprocessed = set(threadData.shared.deeper)
            else:
                break

    except KeyboardInterrupt:
        warnMsg = "user aborted during crawling. sqlmap "
        warnMsg += "will use partial list"
        logger.warning(warnMsg)

    finally:
        clearConsoleLine(True)
        threadData.crawlRedirectFilter = None

        if not threadData.shared.value:
            if not (conf.forms and threadData.shared.formsFound):
                warnMsg = "no usable links found (with GET parameters)"
                if conf.forms:
                    warnMsg += " or forms"
                logger.warning(warnMsg)
        else:
            for url in threadData.shared.value:
                kb.targets.add((urldecode(url, kb.pageEncoding), None, None, None, None))

        if kb.targets:
            if kb.normalizeCrawlingChoice is None:
                message = "do you want to normalize "
                message += "crawling results [Y/n] "

                kb.normalizeCrawlingChoice = readInput(message, default='Y', boolean=True)

            if kb.normalizeCrawlingChoice:
                kb.targets = normalizeCrawlingResults(kb.targets)

            storeResultsToFile(kb.targets)

def normalizeCrawlingResults(targets):
    """
    Collapses crawled targets that differ only in their parameter values (e.g. ?id=1 vs ?id=2),
    keeping one representative per distinct endpoint+parameter-name shape

    >>> sorted(_[0] for _ in normalizeCrawlingResults([("http://h/users/edit?id=1", None, None, None, None), ("http://h/users/edit?id=2", None, None, None, None), ("http://h/products/edit?id=1", None, None, None, None)]))
    ['http://h/products/edit?id=1', 'http://h/users/edit?id=1']
    """

    seen = set()
    results = OrderedSet()

    for target in targets:
        value = "%s%s%s" % (target[0], '&' if '?' in target[0] else '?', target[2] or "")
        # Note: key on the full path (not just the last segment) so distinct endpoints sharing an
        # action name and parameters (e.g. /users/edit?id= vs /products/edit?id=) are not collapsed
        match = re.search(r"\A[^?]+\?.+\Z", value)
        if match:
            key = re.sub(r"=[^=&]*", "=", match.group(0)).strip("&?")
            if '=' in key and key not in seen:
                results.add(target)
                seen.add(key)

    return results

def storeResultsToFile(results):
    if not results:
        return

    if kb.storeCrawlingChoice is None:
        message = "do you want to store crawling results to a temporary file "
        message += "for eventual further processing with other tools [y/N] "

        kb.storeCrawlingChoice = readInput(message, default='N', boolean=True)

    if kb.storeCrawlingChoice:
        handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.CRAWLER, suffix=".csv" if conf.forms else ".txt")
        os.close(handle)

        infoMsg = "writing crawling results to a temporary file '%s' " % filename
        logger.info(infoMsg)

        with openFile(filename, "w+") as f:
            if conf.forms:
                f.write("URL,POST\n")

            for url, _, data, _, _ in results:
                if conf.forms:
                    f.write("%s,%s\n" % (safeCSValue(url), safeCSValue(data or "")))
                else:
                    f.write("%s\n" % url)
