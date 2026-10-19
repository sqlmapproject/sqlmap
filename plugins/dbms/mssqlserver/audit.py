#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import AUDIT_MAX_ROWS
from plugins.generic.audit import Audit as GenericAudit


class Audit(GenericAudit):
    dbms = DBMS.MSSQL
    # Snippets keep an outer WHERE for the existing blind TOP/NOT IN limiter.
    queries = (("identity", ("audit_identity",)), ("permissions", ("audit_permissions",)),
               ("configuration", ("audit_configuration",)), ("linked servers", ("audit_links",)))
    flags = dict((key, ("enabled", "disabled")) for key in ("xp_cmdshell", "clr enabled", "Ole Automation Procedures", "Ad Hoc Distributed Queries"))
    flags.update(dict((key, ("yes", "no")) for key in ("sysadmin", "execute xp_cmdshell", "read configuration metadata", "read linked-server metadata")))

    def failure(self, scope, groups):
        permissions = groups.get("permissions") or {}
        for key, name, target in (("read configuration metadata", "configuration", "master.sys.configurations"),
                                  ("read linked-server metadata", "linked servers", "master.sys.servers")):
            if scope == name and permissions.get(key) == "0":
                return "%s: SELECT permission missing on %s" % (scope, target)
        return GenericAudit.failure(self, scope, groups)

    def explain(self, groups):
        configuration = groups.get("configuration") or {}
        permissions = groups.get("permissions") or {}
        identity = groups.get("identity") or {}
        result = []
        if identity.get("sysadmin") == "1" and configuration.get("xp_cmdshell") == "0":
            if self._auditCanExecute():
                result.append("Command execution: sysadmin can enable xp_cmdshell; use --os-cmd or --os-shell")
            else:
                result.append("Command execution: sysadmin can enable xp_cmdshell; no statement execution route identified")
        elif configuration.get("xp_cmdshell") == "1" and permissions.get("execute xp_cmdshell") == "1":
            if self._auditCanExecute():
                result.append("Command execution: xp_cmdshell enabled and EXECUTE granted; use --os-cmd or --os-shell")
            else:
                result.append("Command execution: xp_cmdshell enabled and EXECUTE granted; no statement execution route identified")
        elif permissions.get("execute xp_cmdshell") == "0":
            result.append("Command execution: EXECUTE permission missing on master.dbo.xp_cmdshell")
        elif configuration.get("xp_cmdshell") == "0":
            result.append("Command execution: xp_cmdshell is disabled")
        links = groups.get("linked servers") or {}
        count = links.get("visible linked servers")
        if count and count.isdigit() and int(count) > AUDIT_MAX_ROWS:
            shown = sum(key.startswith("link ") for key in links)
            result.append("Linked servers: showing %d of %s; use --links for the full list" % (shown, count))
        return result
