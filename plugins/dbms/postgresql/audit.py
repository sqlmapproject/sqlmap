#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from plugins.generic.audit import Audit as GenericAudit


class Audit(GenericAudit):
    dbms = DBMS.PGSQL
    queries = (("identity", ("audit_identity",)), ("configuration", ("audit_configuration",)),
               ("privileges", ("audit_privileges",)))
    flags = dict((key, ("yes", "no")) for key in ("superuser", "bypass RLS", "pg_read_server_files", "pg_write_server_files", "pg_execute_server_program"))

    def explain(self, groups):
        privileges = groups.get("privileges") or {}
        superuser = privileges.get("superuser") == "1"
        result = []
        if superuser or privileges.get("pg_read_server_files") == "1":
            result.append("File read: server-file privilege granted; use --file-read with a server-side path")
        if superuser and self._auditCanExecute():
            result.append("File write: superuser and statement execution available; use --file-write and --file-dest")
        if superuser or privileges.get("pg_execute_server_program") == "1":
            if self._auditCanExecute():
                result.append("Command execution: COPY FROM PROGRAM privilege granted; use --os-cmd or --os-shell")
            else:
                result.append("Command execution: COPY FROM PROGRAM privilege granted; no statement execution route identified")
        if superuser or privileges.get("bypass RLS") == "1":
            result.append("Row security: current role bypasses row-level security")
        return result
