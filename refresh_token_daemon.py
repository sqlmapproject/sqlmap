#!/usr/bin/env python3
"""
refresh_token_daemon.py

Periodically fetch an auth token and write to a file (used by sqlmap --eval).
Configure via env vars or edit the defaults below.
"""

import os
import sys
import time
import json
import tempfile
import traceback
from datetime import datetime
from typing import Optional

import requests

# === CONFIG (edit here or set env vars) ===
AUTH_URL = os.getenv("AUTH_URL", "https://target.example.com/auth")
AUTH_BODY_JSON = os.getenv("AUTH_BODY_JSON")  # example: '{"username":"me","password":"pwd"}'
if AUTH_BODY_JSON is None:
    AUTH_BODY = {"username": "youruser", "password": "yourpass"}
else:
    try:
        AUTH_BODY = json.loads(AUTH_BODY_JSON)
    except Exception:
        print("ERROR: AUTH_BODY_JSON not valid JSON", file=sys.stderr)
        AUTH_BODY = {}

DEFAULT_OUT_UNIX = "/tmp/current_token.txt"
DEFAULT_OUT_WIN = r"C:\temp\current_token.txt"
TOKEN_OUT = os.getenv("TOKEN_OUT", DEFAULT_OUT_UNIX if os.name != "nt" else DEFAULT_OUT_WIN)

TOKEN_JSON_KEY = os.getenv("TOKEN_JSON_KEY", "access_token")  # set to "" to use raw body
REFRESH_TTL = int(os.getenv("REFRESH_TTL", "50"))     # seconds token considered fresh
REFRESH_FREQ = int(os.getenv("REFRESH_FREQ", "10"))   # daemon wake frequency (s)

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "15"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_BACKOFF = float(os.getenv("RETRY_BACKOFF", "2.0"))

def log(msg: str, err: bool = False):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = sys.stderr if err else sys.stdout
    print(f"[{ts}] {msg}", file=out)
    out.flush()

# Cross-platform file lock
if os.name == "nt":
    import msvcrt
    class FileLock:
        def __init__(self, path): self.fp = open(path, "a+b")
        def acquire(self):
            try:
                msvcrt.locking(self.fp.fileno(), msvcrt.LK_NBLCK, 1); return True
            except OSError: return False
        def release(self):
            try: self.fp.seek(0); msvcrt.locking(self.fp.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception: pass
        def close(self): 
            try: self.fp.close()
            except Exception: pass
else:
    import fcntl
    class FileLock:
        def __init__(self, path): self.fp = open(path, "a+")
        def acquire(self):
            try:
                fcntl.flock(self.fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB); return True
            except IOError: return False
        def release(self):
            try: fcntl.flock(self.fp.fileno(), fcntl.LOCK_UN)
            except Exception: pass
        def close(self):
            try: self.fp.close()
            except Exception: pass

def ensure_dir_for_file(path: str):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def atomic_write(path: str, data: str):
    ensure_dir_for_file(path)
    dirpath = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dirpath)
    try:
        with os.fdopen(fd, "w") as tmpf:
            tmpf.write(data); tmpf.flush(); os.fsync(tmpf.fileno())
        os.replace(tmp_path, path)
    except Exception:
        log("ERROR during atomic write: " + traceback.format_exc(), err=True)
        try:
            if os.path.exists(tmp_path): os.remove(tmp_path)
        except Exception: pass

def read_token_file_if_recent(path: str, ttl: int) -> Optional[str]:
    try:
        if os.path.exists(path):
            mtime = os.path.getmtime(path)
            age = time.time() - mtime
            if age <= ttl:
                with open(path, "r") as f: return f.read().strip()
    except Exception: pass
    return None

def fetch_token_from_api() -> Optional[str]:
    attempt = 0; delay = 1.0
    while attempt < MAX_RETRIES:
        attempt += 1
        try:
            log(f"Attempting auth request (attempt {attempt}) to {AUTH_URL}")
            resp = requests.post(AUTH_URL, json=AUTH_BODY, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            if TOKEN_JSON_KEY:
                try:
                    obj = resp.json(); token = obj.get(TOKEN_JSON_KEY)
                    if token: return token.strip()
                    else: log("Token JSON key not found; falling back to raw body", err=True)
                except ValueError:
                    log("Response not JSON; falling back to raw body", err=True)
            text = resp.text.strip()
            return text if text else None
        except Exception as e:
            log(f"Auth request failed: {e}", err=True)
            if attempt < MAX_RETRIES:
                time.sleep(delay); delay *= RETRY_BACKOFF
    return None

def main():
    lockfile_path = TOKEN_OUT + ".lock"
    lock = FileLock(lockfile_path)
    log("Starting refresh_token_daemon")
    log(f"AUTH_URL: {AUTH_URL}")
    log(f"TOKEN_OUT: {TOKEN_OUT}")
    log(f"TOKEN_JSON_KEY: {TOKEN_JSON_KEY!r}")
    log(f"REFRESH_TTL: {REFRESH_TTL}s  REFRESH_FREQ: {REFRESH_FREQ}s")
    ensure_dir_for_file(TOKEN_OUT)
    try:
        while True:
            existing = read_token_file_if_recent(TOKEN_OUT, REFRESH_TTL)
            if existing:
                log(f"Token is fresh (<= {REFRESH_TTL}s). Sleeping {REFRESH_FREQ}s.")
                time.sleep(REFRESH_FREQ); continue
            got_lock = lock.acquire()
            if not got_lock:
                log("Another process refreshing token; waiting."); time.sleep(REFRESH_FREQ); continue
            try:
                existing = read_token_file_if_recent(TOKEN_OUT, REFRESH_TTL)
                if existing:
                    log("Token written by another process while waiting for lock; skipping fetch."); continue
                token = fetch_token_from_api()
                if token:
                    atomic_write(TOKEN_OUT, token)
                    log("Token refreshed and written successfully.")
                else:
                    log("Failed to fetch token after retries; will retry later.", err=True)
            finally:
                lock.release()
            time.sleep(REFRESH_FREQ)
    except KeyboardInterrupt:
        log("Interrupted by user; exiting.")
    except Exception:
        log("Unexpected error: " + traceback.format_exc(), err=True)
    finally:
        try: lock.close()
        except Exception: pass

if __name__ == "__main__":
    main()
