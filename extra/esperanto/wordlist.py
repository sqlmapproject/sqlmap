#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Common table/column names for the brute-force fallback used when the system catalog
is unreadable or unknown (permission wall, exotic/Frankenstein engine, CTF). This is
the "know nothing about the schema, guess the usual names" path - the equivalent of
sqlmap's --common-tables / --common-columns. sqlmap's own (much larger) wordlists are
preferred when this package runs inside the repo; the bundled curated lists below are
the self-contained fallback so the standalone CLI works with no external files.
"""

import os


# curated, most-common first; kept deliberately small so brute-forcing stays practical
# over a slow blind oracle (sqlmap's full lists are used instead when available)
_BUNDLED_TABLES = (
    "users", "user", "admin", "administrator", "accounts", "account", "members",
    "member", "customers", "customer", "clients", "client", "people", "persons",
    "employees", "staff", "contacts", "profiles", "profile", "sessions", "session",
    "orders", "order", "products", "product", "items", "item", "categories",
    "category", "cart", "carts", "invoices", "payments", "transactions", "coupons",
    "rates", "reviews", "ratings", "inventory", "stock", "shipping", "posts", "post",
    "articles", "pages", "page", "comments", "messages", "message", "news", "blog",
    "blogs", "tags", "notifications", "subscriptions", "feedback", "files", "file",
    "uploads", "images", "documents", "media", "config", "configuration", "settings",
    "setting", "options", "preferences", "roles", "role", "permissions", "groups",
    "group", "tokens", "token", "secrets", "secret", "credentials", "passwords",
    "keys", "apikeys", "api_keys", "cards", "creditcards", "credit_cards", "logs",
    "log", "events", "event", "audit", "audit_log", "history", "activity", "data",
    "records", "metadata", "backup", "backups", "temp", "tmp", "test", "flags",
)


_BUNDLED_COLUMNS = (
    "id", "uid", "user_id", "userid", "guid", "name", "username", "uname", "user",
    "login", "handle", "nick", "nickname", "pass", "passwd", "password", "pwd",
    "pass_hash", "password_hash", "hash", "salt", "email", "mail", "e_mail",
    "first_name", "firstname", "fname", "last_name", "lastname", "lname", "fullname",
    "full_name", "surname", "display_name", "phone", "mobile", "tel", "address",
    "addr", "street", "city", "country", "state", "zip", "zipcode", "postcode",
    "dob", "birthdate", "age", "gender", "sex", "role", "roles", "is_admin", "admin",
    "level", "active", "is_active", "enabled", "disabled", "banned", "status",
    "verified", "created", "created_at", "created_on", "updated", "updated_at",
    "modified", "deleted", "deleted_at", "last_login", "timestamp", "date", "time",
    "token", "api_key", "apikey", "session", "secret", "key", "value", "data",
    "content", "body", "text", "title", "subject", "description", "comment", "note",
    "notes", "message", "url", "link", "ip", "ip_address", "useragent", "referer",
    "cc", "card", "creditcard", "credit_card", "card_number", "cvv", "cvc", "expiry",
    "amount", "price", "cost", "total", "balance", "quantity", "qty", "count", "code",
    "type", "category", "tag", "slug", "flag", "flags", "extra", "meta", "settings",
)


def _fromFile(fname):
    # sqlmap's own wordlist when this runs inside the repo (data/txt/<fname>).
    # located relative to this file: extra/esperanto/ -> ../../data/txt/
    path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "txt", fname)
    try:
        with open(path) as fh:
            names = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        return names or None
    except (IOError, OSError):
        return None


def commonTables():
    """Candidate table names, most-common first. sqlmap's list if present, else bundled."""
    return _fromFile("common-tables.txt") or list(_BUNDLED_TABLES)


def commonColumns():
    """Candidate column names, most-common first. sqlmap's list if present, else bundled."""
    return _fromFile("common-columns.txt") or list(_BUNDLED_COLUMNS)
