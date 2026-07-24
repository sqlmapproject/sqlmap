#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Dependency-free KDC discovery for a realm, so '--auth-type=Negotiate' works without an explicit
# KDC address. Resolution order: the 'SQLMAP_KERBEROS_KDC' environment variable, then the local
# krb5.conf [realms] section, then a DNS SRV lookup (_kerberos._tcp.<realm>), then the realm name
# itself as a host. Returns (host, port). Python 2.7 / 3.x.

import os
import re
import socket
import struct

DEFAULT_KDC_PORT = 88
_DNS_TIMEOUT = 3
_SRV_TYPE = 33
_IN_CLASS = 1

def _splitHostPort(value, defaultPort=DEFAULT_KDC_PORT):
    value = value.strip()
    if value.startswith("["):                              # [IPv6] or [IPv6]:port
        host, _, rest = value[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif value.count(":") == 1:                            # host:port (a single colon rules out bare IPv6)
        host, _, port = value.partition(":")
    else:                                                  # bare host or bare IPv6 literal
        host, port = value, ""
    return host, (int(port) if port.isdigit() else defaultPort)

# ---- krb5.conf --------------------------------------------------------------------------------
def _fromKrb5Conf(realm):
    path = os.environ.get("KRB5_CONFIG") or "/etc/krb5.conf"
    try:
        with open(path) as f:
            content = f.read()
    except (IOError, OSError):
        return None

    # scope the search to the [realms] section itself: '[capaths]' uses the identical
    # 'realm = { ... }' syntax, so a same-named capath block must not shadow the real one
    section = re.search(r"(?im)^[ \t]*\[realms\][ \t]*$", content)
    if not section:
        return None
    nextSection = re.search(r"(?m)^[ \t]*\[", content[section.end():])
    sectionEnd = section.end() + nextSection.start() if nextSection else len(content)
    realms = content[section.end():sectionEnd]

    header = re.search(r"(?im)^\s*%s\s*=\s*\{" % re.escape(realm), realms)
    if not header:
        return None
    start = header.end()                                   # brace-match so a nested '{ }' block cannot truncate us
    depth, i = 1, start
    while i < len(realms) and depth > 0:
        if realms[i] == "{":
            depth += 1
        elif realms[i] == "}":
            depth -= 1
        i += 1
    block = realms[start:i - 1]
    kdc = re.search(r"(?im)^\s*kdc\s*=\s*(\S+)", block)
    return kdc.group(1) if kdc else None

# ---- DNS SRV (_kerberos._tcp.<realm>) ---------------------------------------------------------
def _nameservers():
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except (IOError, OSError):
        pass
    return servers

def _encodeName(name):
    out = bytearray()
    for label in name.split("."):
        out.append(len(label))
        out += label.encode("ascii")
    out.append(0)
    return bytes(out)

_MAX_NAME_JUMPS = 64                                       # guards against compression-pointer cycles

def _skipName(data, offset):
    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xc0 == 0xc0:                          # compression pointer ends the name
            if offset + 2 > len(data):
                raise ValueError("truncated DNS pointer")
            return offset + 2
        offset += 1 + length

def _readName(data, offset):
    labels = []
    end = None
    jumps = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xc0 == 0xc0:                          # follow compression pointer (bounded, cycle-safe)
            if offset + 2 > len(data):
                raise ValueError("truncated DNS pointer")
            jumps += 1
            if jumps > _MAX_NAME_JUMPS:
                raise ValueError("too many DNS compression jumps")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3f) << 8) | data[offset + 1]
            continue
        if offset + 1 + length > len(data):
            raise ValueError("truncated DNS label")
        labels.append(bytes(data[offset + 1:offset + 1 + length]).decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), (end if end is not None else offset)

def parseSrv(response):
    """Parse SRV records from a (possibly hostile) DNS response into [(priority, weight, port,
    target), ...]. Malformed input yields an empty list rather than raising."""

    data = bytearray(response)
    if len(data) < 12:
        return []
    try:
        qdcount, ancount = struct.unpack(">HH", bytes(data[4:8]))
        offset = 12
        for _ in range(qdcount):
            offset = _skipName(data, offset) + 4           # + qtype/qclass
        records = []
        for _ in range(ancount):
            offset = _skipName(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, _ttl, rdlength = struct.unpack(">HHIH", bytes(data[offset:offset + 10]))
            offset += 10
            if offset + rdlength > len(data):
                break
            if rtype == _SRV_TYPE and rclass == _IN_CLASS and rdlength >= 6:
                priority, weight, port = struct.unpack(">HHH", bytes(data[offset:offset + 6]))
                target = _readName(data, offset + 6)[0].rstrip(".")
                if target:
                    records.append((priority, weight, port, target))
            offset += rdlength
        return records
    except (ValueError, struct.error, IndexError):
        return []

def _fromDnsSrv(realm):
    queryId = os.urandom(2)
    query = (queryId + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0) +
             _encodeName("_kerberos._tcp.%s" % realm) + struct.pack(">HH", _SRV_TYPE, _IN_CLASS))
    for server in _nameservers():
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(_DNS_TIMEOUT)
        try:
            sock.connect((server, 53))                     # connect() so the kernel drops replies from any other source
            sock.send(query)
            response = sock.recv(4096)
        except socket.error:
            continue
        finally:
            sock.close()
        if len(response) < 2 or response[:2] != queryId:   # ignore stray / spoofed replies
            continue
        records = parseSrv(response)
        if records:
            best = min(records, key=lambda r: (r[0], -r[1]))   # lowest priority, then highest weight
            return best[3], best[2]
    return None

def discoverKdc(realm):
    """Resolve (host, port) of a KDC for the realm; falls back to the realm name itself as a host."""

    override = os.environ.get("SQLMAP_KERBEROS_KDC")
    if override:
        return _splitHostPort(override)

    configured = _fromKrb5Conf(realm)
    if configured:
        return _splitHostPort(configured)

    fromDns = _fromDnsSrv(realm)
    if fromDns:
        return fromDns

    return realm.lower(), DEFAULT_KDC_PORT
