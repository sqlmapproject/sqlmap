#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import logging
import re
import sys

from lib.core.enums import CUSTOM_LOGGING

logging.addLevelName(CUSTOM_LOGGING.PAYLOAD, "PAYLOAD")
logging.addLevelName(CUSTOM_LOGGING.TRAFFIC_OUT, "TRAFFIC OUT")
logging.addLevelName(CUSTOM_LOGGING.TRAFFIC_IN, "TRAFFIC IN")

LOGGER = logging.getLogger("sqlmapLog")

LOGGER_HANDLER = None
try:
    from thirdparty.ansistrm.ansistrm import ColorizingStreamHandler

    class _ColorizingStreamHandler(ColorizingStreamHandler):
        def colorize(self, message, levelno, force=False):
            if levelno in self.level_map and (self.is_tty or force):
                bg, fg, bold = self.level_map[levelno]
                params = []

                if bg in self.color_map:
                    params.append(str(self.color_map[bg] + 40))

                if fg in self.color_map:
                    params.append(str(self.color_map[fg] + 30))

                if bold:
                    params.append('1')

                if params and message:
                    match = re.search(r"\A(\s+)", message)
                    prefix = match.group(1) if match else ""
                    message = message[len(prefix):]

                    match = re.search(r"\[([A-Z ]+)\]", message)  # log level
                    if match:
                        level = match.group(1)
                        if message.startswith(self.bold):
                            message = message.replace(self.bold, "")
                            reset = self.reset + self.bold
                            params.append('1')
                        else:
                            reset = self.reset
                        message = message.replace(level, ''.join((self.csi, ';'.join(params), 'm', level, reset)), 1)

                        match = re.search(r"\A\s*\[([\d:]+)\]", message)  # time
                        if match:
                            time = match.group(1)
                            message = message.replace(time, ''.join((self.csi, str(self.color_map["cyan"] + 30), 'm', time, self._reset(message))), 1)

                        match = re.search(r"\[(#\d+)\]", message)  # counter
                        if match:
                            counter = match.group(1)
                            message = message.replace(counter, ''.join((self.csi, str(self.color_map["yellow"] + 30), 'm', counter, self._reset(message))), 1)

                        if level != "PAYLOAD":
                            if any(_ in message for _ in ("parsed DBMS error message",)):
                                match = re.search(r": '(.+)'", message)
                                if match:
                                    string = match.group(1)
                                    message = message.replace("'%s'" % string, "'%s'" % ''.join((self.csi, str(self.color_map["white"] + 30), 'm', string, self._reset(message))), 1)
                            else:
                                match = re.search(r"\bresumed: '(.+\.\.\.)", message)
                                if match:
                                    string = match.group(1)
                                    message = message.replace("'%s" % string, "'%s" % ''.join((self.csi, str(self.color_map["white"] + 30), 'm', string, self._reset(message))), 1)
                                else:
                                    match = re.search(r" \('(.+)'\)\Z", message) or re.search(r"output: '(.+)'\Z", message)
                                    if match:
                                        string = match.group(1)
                                        message = message.replace("'%s'" % string, "'%s'" % ''.join((self.csi, str(self.color_map["white"] + 30), 'm', string, self._reset(message))), 1)
                                    else:
                                        for match in re.finditer(r"[^\w]'([^']+)'", message):  # single-quoted
                                            string = match.group(1)
                                            message = message.replace("'%s'" % string, "'%s'" % ''.join((self.csi, str(self.color_map["white"] + 30), 'm', string, self._reset(message))), 1)
                    else:
                        message = ''.join((self.csi, ';'.join(params), 'm', message, self.reset))

                    if prefix:
                        message = "%s%s" % (prefix, message)

                    message = message.replace("%s]" % self.bold, "]%s" % self.bold)  # dirty patch

            return message

    disableColor = False

    for argument in sys.argv:
        if "disable-col" in argument:
            disableColor = True
            break

    if disableColor:
        LOGGER_HANDLER = logging.StreamHandler(sys.stdout)
    else:
        LOGGER_HANDLER = _ColorizingStreamHandler(sys.stdout)
        LOGGER_HANDLER.level_map[logging.getLevelName("PAYLOAD")] = (None, "cyan", False)
        LOGGER_HANDLER.level_map[logging.getLevelName("TRAFFIC OUT")] = (None, "magenta", False)
        LOGGER_HANDLER.level_map[logging.getLevelName("TRAFFIC IN")] = ("magenta", None, False)
except ImportError:
    LOGGER_HANDLER = logging.StreamHandler(sys.stdout)

FORMATTER = logging.Formatter("\r[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")

LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.INFO)
