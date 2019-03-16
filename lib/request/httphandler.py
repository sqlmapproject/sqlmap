#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/3/16 2:48 PM
# @Author  : w8ay
# @File    : httphandler.py
import urllib2
import httplib
from lib.core.data import conf


class HTTPHandler(urllib2.HTTPHandler):

    def _hook(self, request):
        host = request.get_host()
        if not host:
            raise urllib2.URLError('no host given')

        if request.has_data():  # POST
            data = request.get_data()
            if not request.has_header('Content-type'):
                request.add_unredirected_header(
                    'Content-type',
                    'application/x-www-form-urlencoded')
            if not request.has_header('Content-length') and not conf.chunk:
                request.add_unredirected_header(
                    'Content-length', '%d' % len(data))

        sel_host = host
        if request.has_proxy():
            scheme, sel = urllib2.splittype(request.get_selector())
            sel_host, sel_path = urllib2.splithost(sel)

        if not request.has_header('Host'):
            request.add_unredirected_header('Host', sel_host)
        for name, value in self.parent.addheaders:
            name = name.capitalize()
            if not request.has_header(name):
                request.add_unredirected_header(name, value)
        return request

    http_request = _hook
