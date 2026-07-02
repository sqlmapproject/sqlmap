#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Library facade for programmatic (in-code) usage: 'import sqlmap; sqlmap.scan(...)'.
#
# This is the code-level sibling of the REST API (lib/utils/api.py): both drive the engine as an
# isolated subprocess for programmatic callers. The public names here are re-exported by sqlmap.py so
# that they are reachable as 'sqlmap.scan', 'sqlmap.scanFromRequest' and 'sqlmap.SqlmapError'.

import json
import os
import sys
import tempfile

__all__ = ["scan", "scanFromRequest", "SqlmapError"]

# Absolute path of the engine entry point (this module lives at <root>/lib/utils/library.py)
SQLMAP_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "sqlmap.py")

class SqlmapError(Exception):
    """
    Raised by the library facade (scan/scanFromRequest) when a scan can not produce a result report
    """

    pass

def _terminateProcess(process):
    """
    Best-effort hard teardown of a scan subprocess together with its whole process group, so a
    timed-out scan never leaves orphaned sqlmap workers behind (POSIX kills the group, others fall
    back to killing the process itself)
    """

    import signal

    try:
        if os.name != "nt" and hasattr(os, "killpg"):
            os.killpg(os.getpgid(process.pid), getattr(signal, "SIGKILL", signal.SIGTERM))
        else:
            process.kill()
    except (OSError, AttributeError):
        try:
            process.kill()
        except (OSError, AttributeError):
            pass

def scan(url=None, requestFile=None, timeout=None, outputDir=None, raw=None, **options):
    """
    Runs a sqlmap scan in a dedicated subprocess and returns its structured result (library usage).

    Keyword options are plain sqlmap option names - exactly the names used in a sqlmap configuration
    file (data/sqlmap.conf) and by the REST API, i.e. the 'conf' names, NOT command line switches. So
    scan(url, technique="BEU", getBanner=True, dumpTable=True, tbl="users", level=3) is equivalent to
    the config file lines 'technique = BEU', 'getBanner = True', 'dumpTable = True', 'tbl = users',
    'level = 3'. Unknown names are rejected. The scan is driven through a generated config file passed
    with '-c' (the same mechanism the REST API uses), so there is a single option namespace and no
    argument escaping. 'raw' takes a list of extra raw command line switches for the rare thing not
    expressible as a config option (e.g. raw=["--fresh-queries"]).

    The engine runs fully out-of-process, so a scan can never affect the calling process (no shared
    global state, no HTTP-stack patching, no risk of the host being exited). The return value is the
    parsed '--report-json' report - the same structure as the REST API '/scan/<id>/data' response: a
    dict with keys 'success', 'data' (a list of {'type_name', 'value'} entries: TARGET, TECHNIQUES,
    BANNER, DUMP_TABLE, ...), 'error' and 'meta'.

    scan() is blocking and thread-safe, so it is both thread- and asyncio-ready: run several at once
    in threads, or from an event loop with 'await loop.run_in_executor(None, functools.partial(scan,
    url, dumpTable=True))'. For unattended/concurrent use the run is hardened like the REST API
    subprocess: batch mode (never prompts) with stdin closed, isolated file descriptors, its own
    output directory (so parallel scans of the same target can not collide on session/dump files and
    nothing accumulates on disk), engine output streamed to a temporary file rather than buffered in
    memory, and - when 'timeout' is set - the whole subprocess group is torn down on expiry. Pass
    'outputDir' to keep the run's files.

    Example:
        import sqlmap
        result = sqlmap.scan("http://target/vuln.php?id=1", dumpTable=True, tbl="users")
    """

    import shutil
    import subprocess
    import time

    from lib.core.common import saveConfig
    from lib.core.optiondict import optDict

    if not (url or requestFile):
        raise SqlmapError("scan() requires either 'url' or 'requestFile'")

    if not os.path.isfile(SQLMAP_FILE):
        raise SqlmapError("could not locate the sqlmap engine ('%s')" % SQLMAP_FILE)

    knownOptions = set()
    for family in optDict.values():
        knownOptions.update(family)

    config = {}
    if url:
        config["url"] = url
    if requestFile:
        config["requestFile"] = requestFile
    config.update(options)

    unknown = [_ for _ in config if _ not in knownOptions]
    if unknown:
        raise SqlmapError("unknown option(s) %s - scan() expects sqlmap option names as used in a configuration file (e.g. getBanner, dumpTable, tbl, technique, level), not command line switches" % ", ".join(repr(_) for _ in sorted(unknown)))

    handle, report = tempfile.mkstemp(prefix="sqlmap-", suffix=".json")
    os.close(handle)

    # Each run gets its own output directory so concurrent scans can not collide on session/dump files
    # and no scan state piles up on disk. A caller-provided 'outputDir' is respected and left in place.
    ownOutput = not outputDir
    if ownOutput:
        outputDir = tempfile.mkdtemp(prefix="sqlmap-output-")

    # engine plumbing goes through the very same option namespace
    config["batch"] = True
    config["disableColoring"] = True
    config["outputDir"] = outputDir
    config["reportJson"] = report

    handle, configFile = tempfile.mkstemp(prefix="sqlmap-", suffix=".conf")
    os.close(handle)
    saveConfig(config, configFile)

    argv = [sys.executable or "python", SQLMAP_FILE, "-c", configFile, "--ignore-stdin"]
    if raw:
        argv += list(raw)

    logHandle, logFile = tempfile.mkstemp(prefix="sqlmap-", suffix=".log")
    devnull = open(os.devnull, "rb")

    kwargs = {"shell": False, "close_fds": os.name != "nt", "cwd": os.path.dirname(SQLMAP_FILE) or '.', "stdin": devnull, "stdout": logHandle, "stderr": subprocess.STDOUT}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    elif sys.version_info >= (3, 2):
        kwargs["start_new_session"] = True                  # own process group -> clean group teardown
    else:
        kwargs["preexec_fn"] = os.setsid

    process = None
    try:
        process = subprocess.Popen(argv, **kwargs)

        if timeout is None:
            process.wait()
        else:
            end = time.time() + timeout
            while process.poll() is None:
                if time.time() > end:
                    _terminateProcess(process)
                    process.wait()
                    raise SqlmapError("scan timed out after %s second(s)" % timeout)
                time.sleep(0.5)

        try:
            with open(report, "rb") as f:
                return json.loads(f.read().decode("utf-8", "replace"))
        except (IOError, OSError, ValueError):
            try:
                with open(logFile, "rb") as f:
                    tail = f.read().decode("utf-8", "replace").strip()
            except (IOError, OSError):
                tail = ""
            raise SqlmapError("scan did not produce a valid report (exit code %s)\n%s" % (getattr(process, "returncode", None), tail[-1000:]))
    finally:
        try:
            os.close(logHandle)
        except OSError:
            pass
        devnull.close()
        for path in (report, logFile, configFile):
            try:
                os.remove(path)
            except OSError:
                pass
        if ownOutput:
            shutil.rmtree(outputDir, ignore_errors=True)

def scanFromRequest(requestFile, **options):
    """
    Convenience wrapper for scan(requestFile=...) - runs a scan from a saved HTTP request file ('-r')
    """

    return scan(requestFile=requestFile, **options)
