#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import AUDIT_MAX_ROWS
from plugins.generic.audit import Audit as GenericAudit


class Audit(GenericAudit):
    dbms = DBMS.ORACLE
    queries = (("identity", ("audit_identity",)), ("configuration", ("audit_configuration",)),
               ("privileges", ("audit_privileges",)), ("directory grants", ("audit_directories",)))

    def explain(self, groups):
        grants = groups.get("directory grants") or {}
        count = grants.get("visible directory grants")
        if count and count.isdigit() and int(count) > AUDIT_MAX_ROWS:
            return ["Directory grants: showing %d of %s" % (len(grants) - 1, count)]
        return []
