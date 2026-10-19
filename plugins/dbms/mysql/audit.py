#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.enums import DBMS, FORK
from plugins.generic.audit import Audit as GenericAudit


class Audit(GenericAudit):
    dbms = DBMS.MYSQL
    flags = dict((key, ("enabled", "disabled")) for key in ("local_infile", "require_secure_transport", "read_only", "super_read_only", "general_log", "log_bin", "skip_networking", "skip_grant_tables"))
    flags["direct FILE grant"] = ("present", "absent")

    def __init__(self):
        configuration = ("audit_configuration_mariadb", "audit_configuration") if Backend.isFork(FORK.MARIADB) else ("audit_configuration", "audit_configuration_mariadb")
        self.queries = (("identity", ("audit_identity",)), ("configuration", configuration),
                        ("file access", ("audit_file_access",)), ("privileges", ("audit_privileges",)))

    def explain(self, groups):
        facts = groups.get("file access") or {}
        privileges = groups.get("privileges") or {}
        result = []
        disabled = False
        if "secure_file_priv" in facts:
            value = facts["secure_file_priv"]
            # MariaDB can expose an unrestricted value as SQL NULL; MySQL can expose
            # its disabled value as the literal string "NULL". Keep the raw fact.
            disabled = (value is None or value.upper() == "NULL") and not Backend.isFork(FORK.MARIADB)
            if disabled:
                result.append("File operations: secure_file_priv=NULL blocks --file-read and --file-write")
            elif not value:
                result.append("File operations: no directory restriction from secure_file_priv")
            else:
                result.append("File operations: --file-read and --file-dest paths must be inside '%s'" % value)
        if privileges.get("direct FILE grant") == "1" and not disabled:
            message = "File read: FILE granted; use --file-read with a server-side path"
            if facts.get("max_allowed_packet"):
                message += " (file size < %s bytes)" % facts["max_allowed_packet"]
            result.append(message)
        return result
