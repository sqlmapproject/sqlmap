#!/usr/bin/env python

"""
vulnserver.py - Trivial SQLi vulnerable HTTP server (Note: for testing purposes)

Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import base64
import json
import random
import re
import sqlite3
import string
import sys
import threading
import traceback

PY3 = sys.version_info >= (3, 0)
UNICODE_ENCODING = "utf-8"
DEBUG = False

if PY3:
    from http.client import FORBIDDEN
    from http.client import INTERNAL_SERVER_ERROR
    from http.client import NOT_FOUND
    from http.client import OK
    from http.server import BaseHTTPRequestHandler
    from http.server import HTTPServer
    from socketserver import ThreadingMixIn
    from urllib.parse import parse_qs
    from urllib.parse import unquote_plus
else:
    from BaseHTTPServer import BaseHTTPRequestHandler
    from BaseHTTPServer import HTTPServer
    from httplib import FORBIDDEN
    from httplib import INTERNAL_SERVER_ERROR
    from httplib import NOT_FOUND
    from httplib import OK
    from SocketServer import ThreadingMixIn
    from urlparse import parse_qs
    from urllib import unquote_plus

SCHEMA = """
    CREATE TABLE users (
        id INTEGER,
        name TEXT,
        surname TEXT,
        PRIMARY KEY (id)
    );
    INSERT INTO users (id, name, surname) VALUES (1, 'luther', 'blisset');
    INSERT INTO users (id, name, surname) VALUES (2, 'fluffy', 'bunny');
    INSERT INTO users (id, name, surname) VALUES (3, 'wu', 'ming');
    INSERT INTO users (id, name, surname) VALUES (4, NULL, 'nameisnull');
    INSERT INTO users (id, name, surname) VALUES (5, 'mark', 'lewis');
    INSERT INTO users (id, name, surname) VALUES (6, 'ada', 'lovelace');
    INSERT INTO users (id, name, surname) VALUES (7, 'grace', 'hopper');
    INSERT INTO users (id, name, surname) VALUES (8, 'alan', 'turing');
    INSERT INTO users (id, name, surname) VALUES (9, 'margaret','hamilton');
    INSERT INTO users (id, name, surname) VALUES (10, 'donald', 'knuth');
    INSERT INTO users (id, name, surname) VALUES (11, 'tim', 'bernerslee');
    INSERT INTO users (id, name, surname) VALUES (12, 'linus', 'torvalds');
    INSERT INTO users (id, name, surname) VALUES (13, 'ken', 'thompson');
    INSERT INTO users (id, name, surname) VALUES (14, 'dennis', 'ritchie');
    INSERT INTO users (id, name, surname) VALUES (15, 'barbara', 'liskov');
    INSERT INTO users (id, name, surname) VALUES (16, 'edsger', 'dijkstra');
    INSERT INTO users (id, name, surname) VALUES (17, 'john', 'mccarthy');
    INSERT INTO users (id, name, surname) VALUES (18, 'leslie', 'lamport');
    INSERT INTO users (id, name, surname) VALUES (19, 'niklaus', 'wirth');
    INSERT INTO users (id, name, surname) VALUES (20, 'bjarne', 'stroustrup');
    INSERT INTO users (id, name, surname) VALUES (21, 'guido', 'vanrossum');
    INSERT INTO users (id, name, surname) VALUES (22, 'brendan', 'eich');
    INSERT INTO users (id, name, surname) VALUES (23, 'james', 'gosling');
    INSERT INTO users (id, name, surname) VALUES (24, 'andrew', 'tanenbaum');
    INSERT INTO users (id, name, surname) VALUES (25, 'yukihiro','matsumoto');
    INSERT INTO users (id, name, surname) VALUES (26, 'radia', 'perlman');
    INSERT INTO users (id, name, surname) VALUES (27, 'katherine','johnson');
    INSERT INTO users (id, name, surname) VALUES (28, 'hady', 'lamarr');
    INSERT INTO users (id, name, surname) VALUES (29, 'frank', 'miller');
    INSERT INTO users (id, name, surname) VALUES (30, 'john', 'steward');

    CREATE TABLE creds (
        user_id INTEGER,
        password_hash TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    INSERT INTO creds (user_id, password_hash) VALUES (1, 'db3a16990a0008a3b04707fdef6584a0');
    INSERT INTO creds (user_id, password_hash) VALUES (2, '4db967ce67b15e7fb84c266a76684729');
    INSERT INTO creds (user_id, password_hash) VALUES (3, 'f5a2950eaa10f9e99896800eacbe8275');
    INSERT INTO creds (user_id, password_hash) VALUES (4, NULL);
    INSERT INTO creds (user_id, password_hash) VALUES (5, '179ad45c6ce2cb97cf1029e212046e81');
    INSERT INTO creds (user_id, password_hash) VALUES (6, '0f1e2d3c4b5a69788796a5b4c3d2e1f0');
    INSERT INTO creds (user_id, password_hash) VALUES (7, 'a1b2c3d4e5f60718293a4b5c6d7e8f90');
    INSERT INTO creds (user_id, password_hash) VALUES (8, '1a2b3c4d5e6f708192a3b4c5d6e7f809');
    INSERT INTO creds (user_id, password_hash) VALUES (9, '9f8e7d6c5b4a3928170605f4e3d2c1b0');
    INSERT INTO creds (user_id, password_hash) VALUES (10, '3c2d1e0f9a8b7c6d5e4f30291807f6e5');
    INSERT INTO creds (user_id, password_hash) VALUES (11, 'b0c1d2e3f405162738495a6b7c8d9eaf');
    INSERT INTO creds (user_id, password_hash) VALUES (12, '6e5d4c3b2a190807f6e5d4c3b2a1908f');
    INSERT INTO creds (user_id, password_hash) VALUES (13, '11223344556677889900aabbccddeeff');
    INSERT INTO creds (user_id, password_hash) VALUES (14, 'ffeeddccbbaa00998877665544332211');
    INSERT INTO creds (user_id, password_hash) VALUES (15, '1234567890abcdef1234567890abcdef');
    INSERT INTO creds (user_id, password_hash) VALUES (16, 'abcdef1234567890abcdef1234567890');
    INSERT INTO creds (user_id, password_hash) VALUES (17, '0a1b2c3d4e5f60718a9b0c1d2e3f4051');
    INSERT INTO creds (user_id, password_hash) VALUES (18, '51f04e3d2c1b0a9871605f4e3d2c1b0a');
    INSERT INTO creds (user_id, password_hash) VALUES (19, '89abcdef0123456789abcdef01234567');
    INSERT INTO creds (user_id, password_hash) VALUES (20, '76543210fedcba9876543210fedcba98');
    INSERT INTO creds (user_id, password_hash) VALUES (21, '13579bdf2468ace013579bdf2468ace0');
    INSERT INTO creds (user_id, password_hash) VALUES (22, '02468ace13579bdf02468ace13579bdf');
    INSERT INTO creds (user_id, password_hash) VALUES (23, 'deadbeefdeadbeefdeadbeefdeadbeef');
    INSERT INTO creds (user_id, password_hash) VALUES (24, 'cafebabecafebabecafebabecafebabe');
    INSERT INTO creds (user_id, password_hash) VALUES (25, '00112233445566778899aabbccddeeff');
    INSERT INTO creds (user_id, password_hash) VALUES (26, 'f0e1d2c3b4a5968778695a4b3c2d1e0f');
    INSERT INTO creds (user_id, password_hash) VALUES (27, '7f6e5d4c3b2a190807f6e5d4c3b2a190');
    INSERT INTO creds (user_id, password_hash) VALUES (28, '908f7e6d5c4b3a291807f6e5d4c3b2a1');
    INSERT INTO creds (user_id, password_hash) VALUES (29, '3049b791fa83e2f42f37bae18634b92d');
    INSERT INTO creds (user_id, password_hash) VALUES (30, 'd59a348f90d757c7da30418773424b5e');

    CREATE TABLE directory (
        dn TEXT,
        uid TEXT,
        cn TEXT,
        sn TEXT,
        givenName TEXT,
        displayName TEXT,
        userPassword TEXT,
        mail TEXT,
        objectClass TEXT,
        objectCategory TEXT,
        ou TEXT,
        title TEXT,
        department TEXT,
        company TEXT,
        o TEXT,
        telephoneNumber TEXT,
        mobile TEXT,
        manager TEXT,
        description TEXT,
        l TEXT,
        st TEXT,
        street TEXT,
        postalCode TEXT,
        c TEXT,
        employeeNumber TEXT,
        employeeType TEXT,
        member TEXT
    );
    -- Column order: dn, uid, cn, sn, givenName, displayName, userPassword, mail,
    --               objectClass, objectCategory, ou, title, department, company, o,
    --               telephoneNumber, mobile, manager, description, l, st, street,
    --               postalCode, c, employeeNumber, employeeType, member
    INSERT INTO directory VALUES ('uid=luther,ou=users,dc=example,dc=com', 'luther', 'Luther Blisset', 'Blisset', 'Luther', 'Luther Blisset', 'db3a16990a0008a3b04707fdef6584a0', 'luther@example.com', 'inetOrgPerson', 'Person', 'users', 'System Administrator', 'IT Operations', 'Example Corp', 'Example', '+1 555 0100', '+1 555 0101', 'uid=ada,ou=users,dc=example,dc=com', 'System administrator', 'London', 'Greater London', '10 Downing Street', 'SW1A 2AA', 'GB', '1001', 'Employee', NULL);
    INSERT INTO directory VALUES ('uid=fluffy,ou=users,dc=example,dc=com', 'fluffy', 'Fluffy Bunny', 'Bunny', 'Fluffy', 'Fluffy Bunny', '4db967ce67b15e7fb84c266a76684729', 'fluffy@example.com', 'inetOrgPerson', 'Person', 'users', 'Security Engineer', 'Security', 'Example Corp', 'Example', '+1 555 0102', '+1 555 0103', NULL, 'Security engineer', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=wu,ou=users,dc=example,dc=com', 'wu', 'Wu Ming', 'Ming', 'Wu', 'Wu Ming', 'f5a2950eaa10f9e99896800eacbe8275', 'wu@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Developer', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=mark,ou=users,dc=example,dc=com', 'mark', 'Mark Lewis', 'Lewis', 'Mark', 'Mark Lewis', '179ad45c6ce2cb97cf1029e212046e81', 'mark@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Project manager', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=ada,ou=users,dc=example,dc=com', 'ada', 'Ada Lovelace', 'Lovelace', 'Ada', 'Ada Lovelace', '0f1e2d3c4b5a69788796a5b4c3d2e1f0', 'ada@example.com', 'inetOrgPerson', 'Person', 'users', 'Mathematician', 'Research', 'Example Corp', 'Example', '+1 555 0104', NULL, NULL, 'Mathematician', 'Cambridge', NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=grace,ou=users,dc=example,dc=com', 'grace', 'Grace Hopper', 'Hopper', 'Grace', 'Grace Hopper', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'grace@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Computer scientist', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=alan,ou=users,dc=example,dc=com', 'alan', 'Alan Turing', 'Turing', 'Alan', 'Alan Turing', '1a2b3c4d5e6f708192a3b4c5d6e7f809', 'alan@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Cryptanalyst', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=margaret,ou=users,dc=example,dc=com', 'margaret', 'Margaret Hamilton', 'Hamilton', 'Margaret', 'Margaret Hamilton', '9f8e7d6c5b4a3928170605f4e3d2c1b0', 'margaret@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Software engineer', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=donald,ou=users,dc=example,dc=com', 'donald', 'Donald Knuth', 'Knuth', 'Donald', 'Donald Knuth', '3c2d1e0f9a8b7c6d5e4f30291807f6e5', 'donald@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Computer scientist', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=tim,ou=users,dc=example,dc=com', 'tim', 'Tim Berners-Lee', 'Berners-Lee', 'Tim', 'Tim Berners-Lee', 'b0c1d2e3f405162738495a6b7c8d9eaf', 'tim@example.com', 'inetOrgPerson', 'Person', 'users', 'Inventor', 'Research', 'Example Corp', 'Example', '+1 555 0105', NULL, NULL, 'Inventor of the Web', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=linus,ou=users,dc=example,dc=com', 'linus', 'Linus Torvalds', 'Torvalds', 'Linus', 'Linus Torvalds', '6e5d4c3b2a190807f6e5d4c3b2a1908f', 'linus@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Kernel developer', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=ken,ou=users,dc=example,dc=com', 'ken', 'Ken Thompson', 'Thompson', 'Ken', 'Ken Thompson', '11223344556677889900aabbccddeeff', 'ken@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Unix co-creator', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=dennis,ou=users,dc=example,dc=com', 'dennis', 'Dennis Ritchie', 'Ritchie', 'Dennis', 'Dennis Ritchie', 'ffeeddccbbaa00998877665544332211', 'dennis@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'C language creator', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=barbara,ou=users,dc=example,dc=com', 'barbara', 'Barbara Liskov', 'Liskov', 'Barbara', 'Barbara Liskov', '1234567890abcdef1234567890abcdef', 'barbara@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Turing Award winner', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('uid=edsger,ou=users,dc=example,dc=com', 'edsger', 'Edsger Dijkstra', 'Dijkstra', 'Edsger', 'Edsger Dijkstra', 'abcdef1234567890abcdef1234567890', 'edsger@example.com', 'inetOrgPerson', 'Person', 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Computer scientist', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('ou=users,dc=example,dc=com', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'organizationalUnit', NULL, 'users', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'User accounts', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('ou=groups,dc=example,dc=com', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'organizationalUnit', NULL, 'groups', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Group entries', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    INSERT INTO directory VALUES ('cn=admins,ou=groups,dc=example,dc=com', NULL, 'admins', NULL, NULL, NULL, NULL, NULL, 'groupOfNames', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Administrators group', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'uid=luther,ou=users,dc=example,dc=com');
    INSERT INTO directory VALUES ('cn=admins,ou=groups,dc=example,dc=com', NULL, 'admins', NULL, NULL, NULL, NULL, NULL, 'groupOfNames', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Administrators group', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'uid=ada,ou=users,dc=example,dc=com');
    INSERT INTO directory VALUES ('cn=developers,ou=groups,dc=example,dc=com', NULL, 'developers', NULL, NULL, NULL, NULL, NULL, 'groupOfNames', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Developers group', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'uid=wu,ou=users,dc=example,dc=com');
    INSERT INTO directory VALUES ('cn=developers,ou=groups,dc=example,dc=com', NULL, 'developers', NULL, NULL, NULL, NULL, NULL, 'groupOfNames', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Developers group', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'uid=linus,ou=users,dc=example,dc=com');
"""

LISTEN_ADDRESS = "localhost"
LISTEN_PORT = 8440

# Minimal MongoDB-style collection backing the NoSQL operator-injection endpoint ('/nosql'). The
# 'password' field is the blind-extraction target, constrained by a sibling 'name' equality match.
NOSQL_USERS = {
    "luther": "s3cr3t",
    "fluffy": "carrot",
    "wu": "shanghai",
}

def nosql_match(params):
    """Emulates a MongoDB find() on NOSQL_USERS: reconstructs the operator object for the 'password'
    field (from bracket-notation 'password[$ne]=...' or a JSON sub-document) and evaluates it against
    the record selected by 'name'. An invalid $regex raises re.error (surfaced as a driver error)."""

    record = NOSQL_USERS.get(params.get("name"))

    spec = params.get("password")
    if isinstance(spec, dict):
        op, value = next(iter(spec.items()), ("$eq", None))
    else:
        op, value = "$eq", spec
        for key in params:
            match = re.match(r"^password\[(\$\w+)\](?:\[\])?$", key)
            if match:
                op, value = match.group(1), params[key]
                break

    if isinstance(value, (tuple, list)):
        value = value[-1] if value else None

    if record is None:
        return False
    elif op == "$ne":
        return record != value
    elif op == "$gt":
        return record > (value or "")
    elif op == "$regex":
        return re.search(value, record) is not None
    else:           # $eq, $in (single-valued here) and any literal equality
        return record == value

# --- XPath endpoint (vulnerable search and login, backed by an in-memory XML document) ------------

XPATH_XML = """<?xml version="1.0" encoding="UTF-8"?>
<directory>
  <department name="IT Operations">
    <user id="1">
      <username>luther</username>
      <realname>Luther Blisset</realname>
      <email>luther@example.com</email>
      <password>db3a16990a0008a3b04707fdef6584a0</password>
      <role>System Administrator</role>
      <location>London</location>
      <phone>+1 555 0100</phone>
    </user>
    <user id="2">
      <username>fluffy</username>
      <realname>Fluffy Bunny</realname>
      <email>fluffy@example.com</email>
      <password>4db967ce67b15e7fb84c266a76684729</password>
      <role>Security Engineer</role>
      <location>Amsterdam</location>
      <phone>+1 555 0102</phone>
    </user>
    <user id="3">
      <username>wu</username>
      <realname>Wu Ming</realname>
      <email>wu@example.com</email>
      <password>f5a2950eaa10f9e99896800eacbe8275</password>
      <role>Network Administrator</role>
      <location>Shanghai</location>
      <phone>+86 21 555 0103</phone>
    </user>
  </department>
  <department name="Engineering">
    <user id="4">
      <username>linus</username>
      <realname>Linus Torvalds</realname>
      <email>linus@example.com</email>
      <password>8e7b6a5c4d321908f7e6d5c4b3a2910f</password>
      <role>Kernel Developer</role>
      <location>Portland</location>
      <phone>+1 555 0200</phone>
    </user>
    <user id="5">
      <username>ada</username>
      <realname>Ada Lovelace</realname>
      <email>ada@example.com</email>
      <password>1a2b3c4d5e6f7081920a1b2c3d4e5f60</password>
      <role>Algorithm Designer</role>
      <location>London</location>
      <phone>+44 20 555 0201</phone>
    </user>
  </department>
  <department name="Management">
    <user id="6">
      <username>grace</username>
      <realname>Grace Hopper</realname>
      <email>grace@example.com</email>
      <password>9e8d7c6b5a493827160e9d8c7b6a5948</password>
      <role>CTO</role>
      <location>New York</location>
      <phone>+1 555 0300</phone>
    </user>
  </department>
</directory>"""

def _xpath_element_to_dict(el):
    """Convert an lxml element to a dict for JSON serialization."""
    retVal = dict(el.attrib)
    retVal["tag"] = el.tag
    retVal["text"] = (el.text or "").strip()
    children = []
    for child in el:
        children.append(_xpath_element_to_dict(child))
    if children:
        retVal["children"] = children
    return retVal

_conn = None
_cursor = None
_lock = None
_server = None
_alive = False
_csrf_token = None

def init(quiet=False):
    global _conn
    global _cursor
    global _lock
    global _csrf_token

    _csrf_token = "".join(random.sample(string.ascii_letters + string.digits, 20))

    _conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    _cursor = _conn.cursor()
    _lock = threading.Lock()

    _cursor.executescript(SCHEMA)

    if quiet:
        global print

        def _(*args, **kwargs):
            pass

        print = _

class ThreadingServer(ThreadingMixIn, HTTPServer):
    def finish_request(self, *args, **kwargs):
        try:
            HTTPServer.finish_request(self, *args, **kwargs)
        except Exception:
            if DEBUG:
                traceback.print_exc()

# Primitive (CRS-style) WAF/IPS emulator used to exercise the automatic WAF/IPS bypass. The request
# surface is normalized like a real WAF (lowercase, comments->space, whitespace compressed) BEFORE
# a cumulative anomaly score is summed; when the score reaches the per-level threshold the request
# is blocked (403 + marker). The rules are shaped so that camouflage tampers (case/whitespace/
# comments) are normalized away and a *structural* substitution (e.g. 'between'/'equaltolike',
# which removes the scored '=' operator) is the genuine bypass - matching real-world behavior.
#
# The emulator also models the OTHER real-world dimension: a scanner-fingerprint rule (mirroring
# CRS 913100) adds a constant score for a recognizable scanner User-Agent that *stacks* with the
# payload score. Its weight is below every threshold, so the scanner UA alone never blocks (benign
# browsing passes), but it tips an otherwise-permitted payload over the threshold - so neutralizing
# the request fingerprint (a non-scanner User-Agent) is itself a genuine bypass, with no SQL tamper.
WAF_NUMERIC_COMPARISON = r"\d+\s*=\s*\d+"       # numeric self-comparison (boolean payloads); the structural lever 'between'/'equaltolike' removes it
WAF_RULES = (
    (r"\bunion\b.{0,40}\bselect\b", 6),
    (r"\binformation_schema\b", 5),
    (r"\b(sleep|benchmark|extractvalue|updatexml|xp_cmdshell|waitfor)\b", 5),
    (r"\b(select|insert|update|delete|drop)\b", 3),
    (WAF_NUMERIC_COMPARISON, 4),
    (r"<script", 6),
)
WAF_THRESHOLD = {1: 6, 2: 4, 3: 2, 4: 8, 5: 5}      # security_level -> cumulative score that triggers a block
WAF_SCANNER_UA = r"(?i)\b(?:sqlmap|nikto|nessus|acunetix|nmap|masscan|w3af|havij|wpscan|dirbuster|arachni)\b"
WAF_SCANNER_UA_WEIGHT = 3       # CRS 913100-style: constant score for a scanner User-Agent, stacked with the payload score

# Levels 4-5 model a libinjection-class WAF (e.g. OWASP CRS rule 942100): ANY boolean-comparison
# fingerprint scores a flat amount REGARDLESS of operator, so '=','LIKE','BETWEEN','IN' are all
# caught equally - structural tampers (between/equaltolike) do NOT help. There, neutralizing the
# scanner fingerprint is the only payload-preserving bypass (level 4); when even that is not enough
# the search must bail honestly (level 5). This mirrors the hardest real-world case.
WAF_LIBINJECTION_LEVELS = (4, 5)
WAF_LIBINJECTION_WEIGHT = 5
WAF_LIBINJECTION = r"(?i)\b(?:and|or)\b.{0,40}(?:=|>|<|\blike\b|\bbetween\b|\bin\b|\brlike\b|\bregexp\b)"

def waf_score(value, ua=None, level=0):
    value = (value or "").lower()
    value = re.sub(r"/\*.*?\*/", " ", value)        # t:replaceComments (note: -> single space, not empty)
    value = re.sub(r"(?:--|#)[^\n]*", " ", value)   # t:removeComments (line comments)
    value = re.sub(r"\s+", " ", value)              # t:compressWhitespace
    libinjection = level in WAF_LIBINJECTION_LEVELS
    retVal = sum(weight for (pattern, weight) in WAF_RULES if not (libinjection and pattern == WAF_NUMERIC_COMPARISON) and re.search(pattern, value))
    if libinjection and re.search(WAF_LIBINJECTION, value):     # operator-agnostic comparison score (tampers cannot remove it)
        retVal += WAF_LIBINJECTION_WEIGHT
    if ua and re.search(WAF_SCANNER_UA, ua):        # scanner-fingerprint score, stacked with the payload score
        retVal += WAF_SCANNER_UA_WEIGHT
    return retVal

# --- LDAP endpoint (vulnerable search and login, backed by the directory table) ------------------

def _ldap_escape_like(value):
    """Escape a value for safe embedding in a SQLite LIKE pattern: backslash, percent,
    and underscore are the only characters with special meaning in LIKE."""
    if value is None:
        return None
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

def _ldap_attr(attr):
    """Map an LDAP attribute name to the directory table column, or None if unknown."""
    valid = {"dn", "uid", "cn", "sn", "givenName", "displayName", "userPassword", "mail", "objectClass", "objectCategory", "ou", "title", "department", "company", "o", "telephoneNumber", "mobile", "manager", "description", "l", "st", "street", "postalCode", "c", "employeeNumber", "employeeType", "member"}
    return attr if attr in valid else None

def _ldap_match(text, start):
    """Find the closing ')' that balances the opening '(' at `start`. Skip escaped
    hex sequences (e.g. \\28 for literal '(' inside a value) but treat every raw ')'
    as a structural closer."""
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return i + 1
        elif ch == '\\':
            i += 1
        i += 1
    return len(text)

def _ldap_parse_value(text, start):
    """Parse an assertion value from filter text at position `start`, handling escape sequences.
    Returns (value, end_pos)."""
    retVal = []
    i = start
    while i < len(text) and text[i] not in (')',):
        if text[i] == '\\' and i + 2 < len(text):
            retVal.append(chr(int(text[i+1:i+3], 16)))
            i += 3
        else:
            retVal.append(text[i])
            i += 1
    return ''.join(retVal), i

def _ldap_filter_to_sql(text, start=0):
    """Convert an LDAP filter substring starting at `start` to a parameterized
    SQLite WHERE clause. Returns (sql_template, params, end_pos) or (None, [], end_pos)
    on parse failure. Values are passed as parameters so that user-controlled
    characters (apostrophe, backslash, etc.) cannot break the SQL string literal."""

    if start >= len(text) or text[start] != '(':
        return None, [], start

    i = start + 1
    if i >= len(text):
        return None, [], start

    op = text[i]
    i += 1

    if op in ('&', '|'):
        # Compound filter: collect all sub-filters
        sub_clauses = []
        sub_params = []
        while i < len(text) and text[i] == '(':
            clause, params, i = _ldap_filter_to_sql(text, i)
            if clause:
                sub_clauses.append(clause)
                sub_params.extend(params)
        # Always use bracket-matched end so nested compounds don't shift the
        # parent's notion of where this child ends (reviewer blocker 3)
        end = _ldap_match(text, start)
        if not sub_clauses:
            return None, [], end
        if len(sub_clauses) == 1:
            return sub_clauses[0], sub_params, end
        joiner = " AND " if op == '&' else " OR "
        return "(%s)" % joiner.join(sub_clauses), sub_params, end

    elif op == '!':
        # NOT filter
        clause, params, i = _ldap_filter_to_sql(text, i)
        end = _ldap_match(text, start)
        if clause:
            return "(NOT (%s))" % clause, params, end
        return None, [], end

    else:
        # Simple filter: attr OP value
        # Re-read from start+1 to get the full attr name
        j = start + 1
        while j < len(text) and text[j] not in ('=', '>', '<', '~', ')'):
            j += 1
        attr = text[start+1:j].strip()
        if not attr:
            return None, [], _ldap_match(text, start)

        col = _ldap_attr(attr)
        if col is None:
            return None, [], _ldap_match(text, start)

        if j >= len(text):
            return None, [], start

        # Check for approx match (~=)
        if text[j] == '~' and j + 1 < len(text) and text[j+1] == '=':
            op_type = '~='
            j += 2
        elif text[j] == '>' and j + 1 < len(text) and text[j+1] == '=':
            op_type = '>='
            j += 2
        elif text[j] == '<' and j + 1 < len(text) and text[j+1] == '=':
            op_type = '<='
            j += 2
        elif text[j] == '=':
            op_type = '='
            j += 1
        else:
            return None, [], _ldap_match(text, start)

        value, _ = _ldap_parse_value(text, j)
        end = _ldap_match(text, start)

        if op_type == '=':
            if value == '*':
                return "(%s IS NOT NULL AND %s != '')" % (col, col), [], end
            elif '*' in value:
                parts = value.split('*')
                if len(parts) == 2 and not parts[0] and not parts[1]:
                    # Just '*' -> presence
                    return "(%s IS NOT NULL AND %s != '')" % (col, col), [], end
                elif len(parts) == 2 and parts[0] and not parts[1]:
                    # 'prefix*' -> anchored prefix match (LDAP semantics)
                    return "(%s LIKE ? ESCAPE '\\')" % col, ["%s%%" % _ldap_escape_like(parts[0])], end
                elif len(parts) == 2 and not parts[0] and parts[1]:
                    # '*suffix' -> anchored suffix match (LDAP semantics)
                    return "(%s LIKE ? ESCAPE '\\')" % col, ["%%%s" % _ldap_escape_like(parts[1])], end
                else:
                    # '*mid*', 'pre*mid*suf', etc. -- split('*') already
                    # partitions the value into literal segments; joining
                    # them with '%' naturally produces the correct anchored
                    # LIKE pattern: empty first/last elements from surrounding
                    # wildcards become leading/trailing '%' automatically.
                    pattern = '%'.join(_ldap_escape_like(p) for p in parts)
                    return "(%s LIKE ? ESCAPE '\\')" % col, [pattern], end
            else:
                return "(%s = ?)" % col, [value], end
        elif op_type == '>=':
            return "(%s >= ?)" % col, [value], end
        elif op_type == '<=':
            return "(%s <= ?)" % col, [value], end
        elif op_type == '~=':
            return "(%s = ?)" % col, [value], end

        return None, [], end


def _ldap_execute(filter_str):
    """Execute an LDAP filter against the directory table. Returns (rows, error_msg)."""
    if not filter_str or not filter_str.strip():
        return None, "Bad search filter"

    # Simple bracket validation
    if filter_str.count('(') != filter_str.count(')'):
        return None, "Bad search filter (-7)"

    try:
        clause, params, _ = _ldap_filter_to_sql(filter_str)
        if not clause:
            return None, "Bad search filter (-7)"

        sql = "SELECT * FROM directory WHERE %s" % clause
        with _lock:
            _cursor.execute(sql, params)
            rows = _cursor.fetchall()
        return rows, None
    except Exception as ex:
        msg = str(ex)
        # Emulate different back-end error messages
        if "no such column" in msg.lower():
            return None, "Bad search filter"
        if "unrecognized" in msg.lower() or "syntax" in msg.lower():
            return None, "Bad search filter (-7)"
        return None, "Bad search filter (%s)" % msg.split(':')[0]

def _ldap_row_to_obj(row):
    """Convert a SQLite row to a dict with non-None attributes."""
    if not row:
        return None
    keys = ("dn", "uid", "cn", "sn", "givenName", "displayName", "userPassword", "mail", "objectClass", "objectCategory", "ou", "title", "department", "company", "o", "telephoneNumber", "mobile", "manager", "description", "l", "st", "street", "postalCode", "c", "employeeNumber", "employeeType", "member")
    return dict((k, row[i]) for i, k in enumerate(keys) if row[i] is not None)

# --- GraphQL endpoint (vulnerable Apollo-style, backed by the same SQLite database) ----------

# Hard-coded introspection response matching the schema below. Every GraphQL tool (including
# sqlmap's --graphql engine) uses this to discover fields, arguments, and types.
def _graphql_introspection():
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "directives": [],
                "types": [
                    {"kind": "OBJECT", "name": "Query", "fields": [
                        {"name": "user", "args": [
                            {"name": "username", "defaultValue": None, "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}}
                        ], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                        {"name": "search", "args": [
                            {"name": "term", "defaultValue": None, "type": {"kind": "SCALAR", "name": "String", "ofType": None}}
                        ], "type": {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "User", "ofType": None}}},
                        {"name": "login", "args": [
                            {"name": "username", "defaultValue": None, "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}},
                            {"name": "password", "defaultValue": None, "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}}
                        ], "type": {"kind": "OBJECT", "name": "AuthPayload", "ofType": None}},
                    ], "inputFields": None, "enumValues": None},
                    {"kind": "OBJECT", "name": "Mutation", "fields": [
                        {"name": "updateUser", "args": [
                            {"name": "id", "defaultValue": None, "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "Int", "ofType": None}}},
                            {"name": "email", "defaultValue": None, "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}}
                        ], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                    ], "inputFields": None, "enumValues": None},
                    {"kind": "INPUT_OBJECT", "name": "UpdateUserInput", "inputFields": [
                        {"name": "id", "defaultValue": None, "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "Int", "ofType": None}}},
                        {"name": "email", "defaultValue": None, "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}}
                    ]},
                    {"kind": "SCALAR", "name": "Int"},
                    {"kind": "SCALAR", "name": "String"},
                    {"kind": "SCALAR", "name": "Boolean"},
                    {"kind": "SCALAR", "name": "Float"},
                    {"kind": "SCALAR", "name": "ID"},
                    {"kind": "OBJECT", "name": "User", "fields": [
                        {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "Int", "ofType": None}},
                        {"name": "name", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        {"name": "surname", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                    ], "inputFields": None, "enumValues": None},
                    {"kind": "OBJECT", "name": "AuthPayload", "fields": [
                        {"name": "token", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        {"name": "user", "args": [], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                    ], "inputFields": None, "enumValues": None},
                ]
            }
        }
    }


def _graphql_arg(raw):
    """Parse a single GraphQL argument value: strip quotes from strings, keep numbers as-is"""
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1].replace('\\"', '"')
    return raw


def _graphql_match(text, start):
    """Index just past the bracket matching the one at text[start] ('(' or '{'), skipping over
    double-quoted strings so brackets inside argument literals (e.g. an injected SQL payload) and
    nested selection sets do not throw off the balance."""

    pairs = {'(': ')', '{': '}'}
    opener, closer = text[start], pairs[text[start]]
    depth, i, n = 0, start, len(text)
    while i < n:
        char = text[i]
        if char == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _graphql_selections(body):
    """Split a selection set into its top-level (alias, field, rawArgs) fields, tolerating aliasing,
    argument literals carrying brackets/quotes, and nested selection sets (which are skipped over)."""

    identifier = re.compile(r'[A-Za-z_]\w*')
    selections, i, n = [], 0, len(body)
    while i < n:
        while i < n and body[i] in ' \t\r\n,':
            i += 1
        match = identifier.match(body, i)
        if not match:
            i += 1
            continue
        name, i = match.group(0), match.end()

        j = i
        while j < n and body[j] in ' \t\r\n':
            j += 1
        if j < n and body[j] == ':':                # 'name' was an alias; the real field follows
            j += 1
            while j < n and body[j] in ' \t\r\n':
                j += 1
            match = identifier.match(body, j)
            if not match:
                continue
            alias, field, i = name, match.group(0), match.end()
        else:
            alias, field = None, name

        while i < n and body[i] in ' \t\r\n':
            i += 1
        rawArgs = ""
        if i < n and body[i] == '(':
            end = _graphql_match(body, i)
            rawArgs, i = body[i + 1:end - 1], end

        while i < n and body[i] in ' \t\r\n':
            i += 1
        if i < n and body[i] == '{':                # skip this field's (possibly nested) selection set
            i = _graphql_match(body, i)

        selections.append((alias, field, rawArgs))
    return selections


def _graphql_resolve(query, variables):
    """Minimal GraphQL resolver: parse the query, call the matching resolver for each top-level field,
    and return (data_dict_or_None, errors_list). Multiple aliased fields are supported in one request
    (alias:field(args){...} ...), so a client can batch independent probes into a single round-trip."""

    variables = variables or {}
    errors = []
    data = {}

    op = "query"
    for keyword in ("mutation", "subscription"):
        if query.strip().startswith(keyword):
            op = keyword
            break

    start = query.find('{')
    if start == -1:
        errors.append({"message": "Cannot parse query", "extensions": {"code": "GRAPHQL_PARSE_FAILED"}})
        return None, errors

    for alias, field, rawArgs in _graphql_selections(query[start + 1:_graphql_match(query, start) - 1]):
        key = alias or field

        # Parse arguments
        args = {}
        for am in re.finditer(r'(\w+)\s*:\s*("(?:[^"\\]|\\.)*"|\$?\w+(?:\.\w+)?)', rawArgs):
            name, val = am.group(1), am.group(2)
            if val.startswith('$'):
                args[name] = variables.get(val[1:], None)
            else:
                args[name] = _graphql_arg(val)

        try:
            if field in ("__typename", "__schema"):
                data[key] = op.title()
            elif field == "user":
                data[key] = _resolver_user(args.get("username"))
            elif field == "search":
                data[key] = _resolver_search(args.get("term"))
            elif field == "login":
                data[key] = _resolver_login(args.get("username"), args.get("password"))
            elif field == "updateUser":
                data[key] = _resolver_updateUser(args.get("id"), args.get("email"))
            else:
                errors.append({"message": "Cannot query field '%s' on type '%s'. Did you mean 'user', 'search', 'login', or 'updateUser'?" % (field, op.title()),
                               "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}})
        except Exception as ex:
            # Leak the backend error through the GraphQL error envelope (as many real servers do
            # in development mode) -- this drives error-based detection
            errors.append({"message": "%s: %s" % (re.search(r"'([^']+)'", str(type(ex))).group(1), ex),
                           "path": [key], "extensions": {"exception": str(ex)}})

    if not data and not errors:
        return None, errors
    return data, errors


# --- Vulnerable resolvers (direct string concatenation into SQLite) ------------------------

def _resolver_user(username):
    if not username:
        return None
    with _lock:
        _cursor.execute("SELECT id, name, surname FROM users WHERE name='%s'" % username)
        row = _cursor.fetchone()
    return {"id": row[0], "name": row[1], "surname": row[2]} if row else None


def _resolver_search(term):
    with _lock:
        _cursor.execute("SELECT id, name, surname FROM users WHERE name LIKE '%%%s%%'" % (term or ""))
        rows = _cursor.fetchall()
    return [{"id": r[0], "name": r[1], "surname": r[2]} for r in (rows or [])]


def _resolver_login(username, password):
    if not username or not password:
        return None
    with _lock:
        _cursor.execute("SELECT u.id, u.name, u.surname FROM users u JOIN creds c ON u.id=c.user_id WHERE u.name='%s' AND c.password_hash='%s'" % (username, password))
        row = _cursor.fetchone()
    if row:
        return {"token": "tok_%d_%s" % (row[0], row[1]), "user": {"id": row[0], "name": row[1], "surname": row[2]}}
    return None  # returns null in data (boolean oracle: true=object, false=null)


def _resolver_updateUser(id_, email):
    with _lock:
        _cursor.execute("UPDATE users SET surname='%s' WHERE id=%s" % (email, id_))
        _cursor.execute("SELECT id, name, surname FROM users WHERE id=%s" % id_)
        row = _cursor.fetchone()
    return {"id": row[0], "name": row[1], "surname": row[2]} if row else None


class ReqHandler(BaseHTTPRequestHandler):
    def do_REQUEST(self):
        path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
        params = {}

        if query:
            params.update(parse_qs(query))

            if "<script>" in unquote_plus(query):
                self.send_response(INTERNAL_SERVER_ERROR)
                self.send_header("X-Powered-By", "Express")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write("CLOUDFLARE_ERROR_500S_BOX".encode(UNICODE_ENCODING))
                return

        if hasattr(self, "data"):
            if self.data.startswith('{') and self.data.endswith('}'):
                params.update(json.loads(self.data))
            elif self.data.startswith('<') and self.data.endswith('>'):
                params.update(dict((_[0], _[1].replace("&apos;", "'").replace("&quot;", '"').replace("&lt;", '<').replace("&gt;", '>').replace("&amp;", '&')) for _ in re.findall(r'name="([^"]+)" value="([^"]*)"', self.data)))
            else:
                self.data = self.data.replace(';', '&')     # Note: seems that Python3 started ignoring parameter splitting with ';'
                params.update(parse_qs(self.data))

        for name in self.headers:
            params[name.lower()] = self.headers[name]

        if "cookie" in params:
            for part in params["cookie"].split(';'):
                part = part.strip()
                if '=' in part:
                    name, value = part.split('=', 1)
                    params[name.strip()] = unquote_plus(value.strip())

        for key in params:
            if params[key] and isinstance(params[key], (tuple, list)):
                params[key] = params[key][-1]

        self.url, self.params = path, params

        # primitive WAF/IPS emulator (opt-in via 'security_level' param; 0/absent = off)
        try:
            level = int(self.params.get("security_level", 0) or 0)
        except (TypeError, ValueError):
            level = 0

        if level > 0:
            surface = "%s %s" % (unquote_plus(query), getattr(self, "data", "") or "")
            if waf_score(surface, ua=self.params.get("user-agent"), level=level) >= WAF_THRESHOLD.get(level, 2):
                self.send_response(FORBIDDEN)
                self.send_header("Content-type", "text/html; charset=%s" % UNICODE_ENCODING)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"<html><body>Request blocked: security policy violation (WAF)</body></html>")
                return

        if self.url == "/csrf":
            if self.params.get("csrf_token") == _csrf_token:
                self.url = "/"
            else:
                self.send_response(OK)
                self.send_header("Content-type", "text/html; charset=%s" % UNICODE_ENCODING)
                self.end_headers()

                form = (
                    "<html><body>"
                    "CSRF protection check<br>"
                    "<form action='/csrf' method='POST'>"
                    "<input type='hidden' name='csrf_token' value='%s'>"
                    "id: <input type='text' name='id'>"
                    "<input type='submit' value='Submit'>"
                    "</form>"
                    "</body></html>"
                ) % _csrf_token

                self.wfile.write(form.encode(UNICODE_ENCODING))
                return

        if self.url == "/nosql":
            self.send_response(OK)
            self.send_header("Content-type", "text/html; charset=%s" % UNICODE_ENCODING)
            self.send_header("Connection", "close")
            self.end_headers()

            try:
                output = "<html><body><b>Welcome %s</b></body></html>" % self.params.get("name") if nosql_match(self.params) else "<html><body><b>Invalid credentials</b></body></html>"
            except re.error:       # invalid $regex -> emulate a MongoDB driver error (drives fingerprinting)
                output = "<html><body>MongoServerError: Regular expression is invalid: missing terminating ] for character class</body></html>"

            self.wfile.write(output.encode(UNICODE_ENCODING))
            return

        if self.url == "/graphql":
            self.send_response(OK)
            self.send_header("Content-type", "application/json; charset=%s" % UNICODE_ENCODING)
            self.send_header("Connection", "close")
            self.end_headers()

            query = self.params.get("query", "")
            variables = self.params.get("variables") or {}

            if not isinstance(variables, dict):
                try:
                    variables = json.loads(str(variables))
                except Exception:
                    variables = {}

            if "__schema" in query:
                output = json.dumps(_graphql_introspection())
            else:
                data, errors = _graphql_resolve(query, variables)
                resp = {}
                if errors:
                    resp["errors"] = errors
                if data:
                    resp["data"] = data
                output = json.dumps(resp, default=str)

            self.wfile.write(output.encode(UNICODE_ENCODING))
            return

        if self.url in ("/ldap", "/ldap/search"):
            self.send_response(OK)
            self.send_header("Content-type", "application/json; charset=%s" % UNICODE_ENCODING)
            self.send_header("Connection", "close")
            self.end_headers()

            q = self.params.get("q", "")
            if q:
                filter_str = "(|(cn=*%s*)(sn=*%s*)(mail=*%s*)(uid=*%s*)(description=*%s*))" % (q, q, q, q, q)
                rows, error = _ldap_execute(filter_str)
                if error:
                    output = json.dumps({"resultCode": 1, "errorMessage": error})
                else:
                    entries = [_ldap_row_to_obj(r) for r in (rows or [])]
                    output = json.dumps({"resultCode": 0, "entries": entries, "count": len(entries)}, default=str)
            else:
                output = json.dumps({"resultCode": 0, "entries": [], "count": 0})

            self.wfile.write(output.encode(UNICODE_ENCODING))
            return

        if self.url == "/ldap/login":
            self.send_response(OK)
            self.send_header("Content-type", "application/json; charset=%s" % UNICODE_ENCODING)
            self.send_header("Connection", "close")
            self.end_headers()

            user = self.params.get("user", "")
            password = self.params.get("pass", "")
            if user and password:
                filter_str = "(&(uid=%s)(userPassword=%s))" % (user, password)
                rows, error = _ldap_execute(filter_str)
                if error:
                    output = json.dumps({"resultCode": 49, "errorMessage": error})
                elif rows:
                    entry = _ldap_row_to_obj(rows[0])
                    output = json.dumps({"resultCode": 0, "authenticated": True, "user": entry}, default=str)
                else:
                    output = json.dumps({"resultCode": 49, "authenticated": False, "errorMessage": "Invalid credentials"})
            else:
                output = json.dumps({"resultCode": 49, "authenticated": False, "errorMessage": "Missing credentials"})

            self.wfile.write(output.encode(UNICODE_ENCODING))
            return

        if self.url == "/xpath/search":
            self.send_response(OK)
            self.send_header("Content-type", "application/json; charset=%s" % UNICODE_ENCODING)
            self.send_header("Connection", "close")
            self.end_headers()

            q = self.params.get("q", "")
            entries = []
            error = None

            if q:
                try:
                    from lxml import etree
                    root = etree.fromstring(XPATH_XML.encode("utf-8"))
                    # VULNERABLE: unsanitized user input directly interpolated into XPath
                    xpath_expr = "/directory/department/user[contains(username,'%s') or contains(realname,'%s')]" % (q, q)
                    elements = root.xpath(xpath_expr)
                    entries = [_xpath_element_to_dict(el) for el in elements]
                except Exception as ex:
                    error = "%s: %s" % (type(ex).__name__, str(ex))

            output = json.dumps({"entries": entries, "count": len(entries), "error": error}, default=str)
            self.wfile.write(output.encode(UNICODE_ENCODING))
            return

        if self.url == "/xpath/login":
            self.send_response(OK)
            self.send_header("Content-type", "application/json; charset=%s" % UNICODE_ENCODING)
            self.send_header("Connection", "close")
            self.end_headers()

            username = self.params.get("username", "")
            password = self.params.get("password", "")
            error = None
            authenticated = False

            if username and password:
                try:
                    from lxml import etree
                    root = etree.fromstring(XPATH_XML.encode("utf-8"))
                    # VULNERABLE: unsanitized interpolation into XPath login expression
                    xpath_expr = "/directory/department/user[username='%s' and password='%s']" % (username, password)
                    results = root.xpath(xpath_expr)
                    if results:
                        authenticated = True
                except Exception as ex:
                    error = "%s: %s" % (type(ex).__name__, str(ex))

            output = json.dumps({"authenticated": authenticated, "error": error}, default=str)
            self.wfile.write(output.encode(UNICODE_ENCODING))
            return

        if self.url == "/ssti/search":
            self.send_response(OK)
            self.send_header("Content-type", "text/html; charset=%s" % UNICODE_ENCODING)
            self.send_header("Connection", "close")
            self.end_headers()

            q = self.params.get("q", "")
            output = "<html><body>"

            if q:
                try:
                    from jinja2 import Template
                    # VULNERABLE: unsanitized user input passed to Jinja2 template engine
                    template = Template("Hello " + q)
                    output += template.render()
                except Exception as ex:
                    # Leak template engine error for error-based detection
                    output += "<b>%s: %s</b>" % (type(ex).__name__, str(ex))
            else:
                output += "Hello"

            output += "</body></html>"
            self.wfile.write(output.encode(UNICODE_ENCODING))
            return

        if self.url == '/':
            if not any(_ in self.params for _ in ("id", "query")):
                self.send_response(OK)
                self.send_header("Content-type", "text/html; charset=%s" % UNICODE_ENCODING)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"<!DOCTYPE html><html><head><title>vulnserver</title></head><body><h3>GET:</h3><a href='/?id=1'>link</a><hr><h3>POST:</h3><form method='post'>ID: <input type='text' name='id'><input type='submit' value='Submit'></form></body></html>")
            else:
                code, output = OK, "<body><html>"
                contentType = "text/html"

                try:
                    if self.params.get("echo", ""):
                        output += "%s<br>" % self.params["echo"]

                    if self.params.get("reflect", ""):
                        output += "%s<br>" % self.params.get("id")

                    with _lock:
                        if "query" in self.params:
                            _cursor.execute(self.params["query"])
                        elif "id" in self.params:
                            if "base64" in self.params:
                                _cursor.execute("SELECT * FROM users WHERE id=%s LIMIT 0, 1" % base64.b64decode("%s===" % self.params["id"], altchars=self.params.get("altchars")).decode())
                            else:
                                _cursor.execute("SELECT * FROM users WHERE id=%s LIMIT 0, 1" % self.params["id"])
                        results = _cursor.fetchall()

                    if self.params.get("json", ""):
                        # JSON response mode: serialize the SAME query results as application/json
                        # (exercises the structure-aware comparison oracle end to end). HTML branches
                        # below are untouched, so existing tests are unaffected.
                        if self.params.get("code", "") and not results:
                            code = INTERNAL_SERVER_ERROR
                        else:
                            contentType = "application/json"
                            output = json.dumps({"results": [list(row) for row in results], "count": len(results)})
                    else:
                        output += "<b>SQL results:</b><br>\n"

                        if self.params.get("code", ""):
                            if not results:
                                code = INTERNAL_SERVER_ERROR
                        else:
                            if results:
                                output += "<table border=\"1\">\n"

                                for row in results:
                                    output += "<tr>"
                                    for value in row:
                                        output += "<td>%s</td>" % value
                                    output += "</tr>\n"

                                output += "</table>\n"
                            else:
                                output += "no results found"

                            if not results:
                                output = "<title>No results</title>" + output
                            else:
                                output = "<title>Results</title>" + output

                        output += "</body></html>"
                except Exception as ex:
                    code = INTERNAL_SERVER_ERROR
                    output = "%s: %s" % (re.search(r"'([^']+)'", str(type(ex))).group(1), ex)

                self.send_response(code)

                self.send_header("Content-type", contentType)
                self.send_header("Connection", "close")

                if self.raw_requestline.startswith(b"HEAD"):
                    self.send_header("Content-Length", str(len(output)))
                    self.end_headers()
                else:
                    self.end_headers()
                    self.wfile.write(output if isinstance(output, bytes) else output.encode(UNICODE_ENCODING))
        else:
            self.send_response(NOT_FOUND)
            self.send_header("Connection", "close")
            self.end_headers()

    def do_GET(self):
        self.do_REQUEST()

    def do_PUT(self):
        self.do_POST()

    def do_HEAD(self):
        self.do_REQUEST()

    def do_POST(self):
        length = int(self.headers.get("Content-length", 0))
        if length:
            data = self.rfile.read(length)
            data = unquote_plus(data.decode(UNICODE_ENCODING, "ignore"))
            self.data = data
        elif self.headers.get("Transfer-encoding") == "chunked":
            data, line = b"", b""
            count = 0

            while True:
                line += self.rfile.read(1)
                if line.endswith(b'\n'):
                    if count % 2 == 1:
                        current = line.rstrip(b"\r\n")
                        if not current:
                            break
                        else:
                            data += current

                    count += 1
                    line = b""

            self.data = data.decode(UNICODE_ENCODING, "ignore")

        self.do_REQUEST()

    def log_message(self, format, *args):
        return

def run(address=LISTEN_ADDRESS, port=LISTEN_PORT):
    global _alive
    global _server
    try:
        _alive = True
        _server = ThreadingServer((address, port), ReqHandler)
        print("[i] running HTTP server at 'http://%s:%d'" % (address, port))
        _server.serve_forever()
    except KeyboardInterrupt:
        _server.socket.close()
        raise
    finally:
        _alive = False

if __name__ == "__main__":
    try:
        init()
        run(sys.argv[1] if len(sys.argv) > 1 else LISTEN_ADDRESS, int(sys.argv[2] if len(sys.argv) > 2 else LISTEN_PORT))
    except KeyboardInterrupt:
        print("\r[x] Ctrl-C received")
