#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Internationalization (i18n) support using GNU gettext.
"""

import gettext
import os
import sys

_LOCALE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "locales")

_DOMAIN = "sqlmap"

_translation = None

def init(language=None):
    """
    Initialize gettext translation.
    
    If no language is specified, try to detect from system locale.
    """
    global _translation

    if language is None:
        import locale
        try:
            language, _ = locale.getdefaultlocale()
        except Exception:
            language = os.environ.get("LANG", "en_US.UTF-8")

    if language:
        language = language.split(".")[0]  # e.g., "zh_CN.UTF-8" -> "zh_CN"

    try:
        if language and language != "en_US":
            _translation = gettext.translation(
                _DOMAIN,
                localedir=_LOCALE_DIR,
                languages=[language],
                fallback=True
            )
        else:
            _translation = gettext.NullTranslations()
    except Exception:
        _translation = gettext.NullTranslations()

    # Install the _() function into builtins so it's available everywhere
    if isinstance(_translation, gettext.NullTranslations):
        import builtins
        builtins.__dict__["_"] = lambda msg: msg
    else:
        _translation.install()


def _(message):
    """
    Translate a message.
    """
    global _translation
    if _translation is None:
        init()
    return _translation.gettext(message) if _translation else message
