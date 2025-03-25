#
# Copyright (C) 2010-2012 Vinay Sajip. All rights reserved. Licensed under the new BSD license.
# (Note: 2018 modifications by @stamparm)
#

import logging
import re
import sys

from lib.core.settings import IS_WIN

if IS_WIN:
    import ctypes
    import ctypes.wintypes

    # Reference: https://gist.github.com/vsajip/758430
    #            https://github.com/ipython/ipython/issues/4252
    #            https://msdn.microsoft.com/en-us/library/windows/desktop/ms686047%28v=vs.85%29.aspx
    ctypes.windll.kernel32.SetConsoleTextAttribute.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.WORD]
    ctypes.windll.kernel32.SetConsoleTextAttribute.restype = ctypes.wintypes.BOOL

def stdoutEncode(data):  # Cross-referenced function
    return data

class ColorizingStreamHandler(logging.StreamHandler):
    # color names to indices
    color_map = {
        'black': 0,
        'red': 1,
        'green': 2,
        'yellow': 3,
        'blue': 4,
        'magenta': 5,
        'cyan': 6,
        'white': 7,
    }

    # levels to (background, foreground, bold/intense)
    level_map = {
        logging.DEBUG: (None, 'blue', False),
        logging.INFO: (None, 'green', False),
        logging.WARNING: (None, 'yellow', False),
        logging.ERROR: (None, 'red', False),
        logging.CRITICAL: ('red', 'white', False)
    }
    csi = '\x1b['
    reset = '\x1b[0m'
    bold = "\x1b[1m"
    disable_coloring = False

    @property
    def is_tty(self):
        isatty = getattr(self.stream, 'isatty', None)
        return isatty and isatty() and not self.disable_coloring

    def emit(self, record):
        try:
            message = stdoutEncode(self.format(record))
            stream = self.stream

            if not self.is_tty:
                if message and message[0] == "\r":
                    message = message[1:]
                stream.write(message)
            else:
                self.output_colorized(message)
            stream.write(getattr(self, 'terminator', '\n'))

            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except IOError:
            pass
        except:
            self.handleError(record)

    if not IS_WIN:
        def output_colorized(self, message):
            self.stream.write(message)
    else:
        ansi_esc = re.compile(r'\x1b\[((?:\d+)(?:;(?:\d+))*)m')

        nt_color_map = {
            0: 0x00,    # black
            1: 0x04,    # red
            2: 0x02,    # green
            3: 0x06,    # yellow
            4: 0x01,    # blue
            5: 0x05,    # magenta
            6: 0x03,    # cyan
            7: 0x07,    # white
        }

        def output_colorized(self, message):
            parts = self.ansi_esc.split(message)
            h = None
            fd = getattr(self.stream, 'fileno', None)

            if fd is not None:
                fd = fd()

                if fd in (1, 2): # stdout or stderr
                    h = ctypes.windll.kernel32.GetStdHandle(-10 - fd)

            while parts:
                text = parts.pop(0)

                if text:
                    self.stream.write(text)
                    self.stream.flush()

                if parts:
                    params = parts.pop(0)

                    if h is not None:
                        params = [int(p) for p in params.split(';')]
                        color = 0

                        for p in params:
                            if 40 <= p <= 47:
                                color |= self.nt_color_map[p - 40] << 4
                            elif 30 <= p <= 37:
                                color |= self.nt_color_map[p - 30]
                            elif p == 1:
                                color |= 0x08 # foreground intensity on
                            elif p == 0: # reset to default color
                                color = 0x07
                            else:
                                pass # error condition ignored

                        ctypes.windll.kernel32.SetConsoleTextAttribute(h, color)

    def _reset(self, message):
        if not message.endswith(self.reset):
            reset = self.reset
        elif self.bold in message:  # bold
            reset = self.reset + self.bold
        else:
            reset = self.reset

        return reset

    def colorize(self, message, levelno):
        if levelno in self.level_map and self.is_tty:
            bg, fg, bold = self.level_map[levelno]
            params = []

            if bg in self.color_map:
                params.append(str(self.color_map[bg] + 40))

            if fg in self.color_map:
                params.append(str(self.color_map[fg] + 30))

            if bold:
                params.append('1')

            if params and message:
                if message.lstrip() != message:
                    prefix = re.search(r"\s+", message).group(0)
                    message = message[len(prefix):]
                else:
                    prefix = ""

                message = "%s%s" % (prefix, ''.join((self.csi, ';'.join(params),
                                   'm', message, self.reset)))

        return message

    def format(self, record):
        message = logging.StreamHandler.format(self, record)
        return self.colorize(message, record.levelno)
