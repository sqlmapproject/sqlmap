#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import logger


class RequestCollectorFactory:

    def __init__(self, collect=False):
        self.collect = collect

    def create(self):
        collector = RequestCollector()

        if not self.collect:
            collector.collectRequest = self._noop

        return collector

    @staticmethod
    def _noop(*args, **kwargs):
        pass


class RequestCollector:

    def collectRequest(self, requestMessage, responseMessage):
        logger.info("Received request/response: %s/%s", len(requestMessage), len(responseMessage))
