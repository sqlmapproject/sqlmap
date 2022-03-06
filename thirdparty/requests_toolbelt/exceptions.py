# -*- coding: utf-8 -*-
"""Collection of exceptions raised by requests-toolbelt."""


class StreamingError(Exception):
    """Used in :mod:`requests_toolbelt.downloadutils.stream`."""
    pass


class VersionMismatchError(Exception):
    """Used to indicate a version mismatch in the version of requests required.

    The feature in use requires a newer version of Requests to function
    appropriately but the version installed is not sufficient.
    """
    pass


class RequestsVersionTooOld(Warning):
    """Used to indicate that the Requests version is too old.

    If the version of Requests is too old to support a feature, we will issue
    this warning to the user.
    """
    pass


class IgnoringGAECertificateValidation(Warning):
    """Used to indicate that given GAE validation behavior will be ignored.

    If the user has tried to specify certificate validation when using the
    insecure AppEngine adapter, it will be ignored (certificate validation will
    remain off), so we will issue this warning to the user.

    In :class:`requests_toolbelt.adapters.appengine.InsecureAppEngineAdapter`.
    """
    pass
