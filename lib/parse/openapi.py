#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import json
import re

from lib.core.common import getSafeExString
from lib.core.data import logger
from lib.core.enums import HTTP_HEADER
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from thirdparty import six
from thirdparty.six.moves.urllib.parse import quote as _quote

try:
    import yaml                                          # optional (only needed for YAML specs)
except ImportError:
    yaml = None

# Best-effort extraction of concrete request targets from an OpenAPI (v3) / Swagger (v2) document. The
# document is treated as a request generator, NOT a contract to validate: for every operation a single
# concrete request is synthesized (base URL + filled path + example query/body from the schema) and any
# operation that cannot be built is skipped with a warning, so a loose/incomplete spec degrades gracefully.

MAX_REF_DEPTH = 25

def _loadSpec(content):
    try:
        return json.loads(content)
    except ValueError:
        if yaml is None:
            errMsg = "the provided OpenAPI/Swagger specification is not JSON and the optional "
            errMsg += "'pyyaml' module (needed for YAML specifications) is not available"
            raise ValueError(errMsg)
        try:
            return yaml.safe_load(content)
        except Exception as ex:
            raise ValueError("not valid JSON nor YAML (%s)" % getSafeExString(ex))

def _resolve(spec, node, seen=None, depth=0):
    seen = seen or set()
    if isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, six.string_types):         # malformed '$ref' (non-string) -> treat as no ref
            return {}
        if ref in seen or depth > MAX_REF_DEPTH:
            return {}
        if not ref.startswith("#/"):
            logger.warning("skipping external OpenAPI $ref '%s'" % ref)
            return {}
        seen = seen | set([ref])
        current = spec
        for part in ref[2:].split('/'):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or part not in current:
                logger.warning("skipping dangling OpenAPI $ref '%s'" % ref)
                return {}
            current = current[part]
        return _resolve(spec, current, seen, depth + 1)
    return node

EXAMPLE_MAX_DEPTH = 8   # request examples do not need deep nesting; caps runaway synthesis on large specs

def _example(spec, schema, seen=None, depth=0, cache=None):
    # 'cache' memoizes the synthesized example per $ref across the whole run - big real-world specs
    # (Stripe/GitHub/k8s) reuse the same large schemas across thousands of operations, so without this
    # the extraction is exponential. 'depth' caps recursion for deeply nested / self-referential schemas.
    seen = seen or set()
    if cache is None:
        cache = {}
    if depth > EXAMPLE_MAX_DEPTH:
        return "1"
    ref = schema.get("$ref") if isinstance(schema, dict) else None
    if not isinstance(ref, six.string_types):             # only a string $ref is a valid (hashable) cache key
        ref = None
    if ref is not None and ref in cache:
        return cache[ref]

    schema = _resolve(spec, schema or {}, seen, depth)
    if not isinstance(schema, dict):
        return "1"

    value = None
    if "example" in schema:
        value = schema["example"]
    elif "const" in schema:                               # JSON Schema 2020-12 (OpenAPI 3.1)
        value = schema["const"]
    elif "default" in schema:
        value = schema["default"]
    elif isinstance(schema.get("examples"), list) and schema["examples"]:
        value = schema["examples"][0]
    elif isinstance(schema.get("enum"), list) and schema["enum"]:
        value = schema["enum"][0]
    else:
        combinator = next((_ for _ in ("allOf", "oneOf", "anyOf") if schema.get(_)), None)
        if combinator:
            if combinator == "allOf":
                merged = {}
                for sub in schema[combinator]:
                    part = _example(spec, sub, seen, depth + 1, cache)
                    if isinstance(part, dict):
                        merged.update(part)
                value = merged if merged else _example(spec, schema[combinator][0], seen, depth + 1, cache)
            else:
                value = _example(spec, schema[combinator][0], seen, depth + 1, cache)
        else:
            _type = schema.get("type")
            if isinstance(_type, list):                    # OpenAPI 3.1 allows a list of types (e.g. ["string", "null"])
                _type = next((_ for _ in _type if _ != "null"), None)
            if _type == "object" or ("properties" in schema and not _type):
                properties = schema.get("properties")
                value = dict((name, _example(spec, sub, seen, depth + 1, cache)) for name, sub in (properties if isinstance(properties, dict) else {}).items())
            elif _type == "array":
                value = [_example(spec, schema.get("items") or {}, seen, depth + 1, cache)]
            elif _type in ("integer", "number"):
                value = 1
            elif _type == "boolean":
                value = True
            elif _type == "string":
                formats = {"uuid": "11111111-1111-1111-1111-111111111111", "date": "2020-01-01", "date-time": "2020-01-01T00:00:00Z", "email": "a@b.co", "byte": "MQ=="}
                value = formats.get(schema.get("format"), "1")
            else:
                value = "1"

    if ref is not None:
        cache[ref] = value
    return value

def _scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, six.string_types):
        return value
    try:
        return json.dumps(value)
    except TypeError:                                     # e.g. datetime.date from a YAML 'example: 2020-01-01'
        return str(value)

_NO_EXAMPLE = object()

def _explicitExample(spec, container):
    # a concrete 'example'/'examples' declared on a parameter or media-type object - preferred over a
    # schema-synthesized value (real specs carry the canonical, validation-passing sample here). 'examples'
    # is a map of name -> {"value": ...} (each entry possibly a $ref).
    if not isinstance(container, dict):
        return _NO_EXAMPLE
    if container.get("example") is not None:              # 'null' -> treat as absent, fall back to schema synthesis
        return container["example"]
    examples = container.get("examples")
    if isinstance(examples, dict) and examples:
        first = _resolve(spec, next(iter(examples.values())))
        if isinstance(first, dict) and first.get("value") is not None:
            return first["value"]
    return _NO_EXAMPLE

def _noMark(text):
    # strip any custom injection mark already present in a synthesized value so only the intentionally
    # appended mark (if any) survives (avoids a stray/second injection point)
    return text.replace(CUSTOM_INJECTION_MARK_CHAR, "")

def _headerClean(text):
    # remove characters that can not legally appear in an HTTP header name/value (CR, LF, NUL and other
    # C0 controls) so a spec-supplied header can not inject extra headers or corrupt the request line
    return re.sub(r"[\x00-\x1f\x7f]", "", text)

_HEADER_NAME_RE = re.compile(r"\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")   # RFC 7230 header field-name token (no spaces / ':' / separators)

def _urlSafe(value, safe=""):
    # percent-encode a synthesized value/name so it can not break the URL/body structure (spaces, '&',
    # '=', '/', '?', '#', ...); py2/py3-safe (py2 urllib.quote needs bytes for non-ASCII). 'safe' keeps
    # selected chars unescaped (e.g. "[]" for deep-object parameter names like filter[status]).
    try:
        return _quote(value.encode("utf-8") if isinstance(value, six.text_type) else str(value), safe=safe)
    except Exception:
        return value

def _baseUrl(spec, origin=None, servers=None):
    # defensive throughout: a hostile/loose spec must not crash here (this runs outside the per-operation
    # try/except, so an exception would abort the whole extraction). 'servers' overrides the spec-level
    # 'servers' (used for per-path / per-operation 'servers').
    basePath = spec.get("basePath") if isinstance(spec.get("basePath"), six.string_types) else ""
    if basePath and not basePath.startswith("/"):         # Swagger v2 basePath is a path -> ensure it is slash-prefixed
        basePath = "/" + basePath
    servers = servers if servers is not None else spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url")
        url = url if isinstance(url, six.string_types) else ""
        variables = servers[0].get("variables")
        if isinstance(variables, dict):
            for name, meta in variables.items():
                default = meta.get("default", "1") if isinstance(meta, dict) else "1"
                url = url.replace("{%s}" % name, str(default))
        if re.match(r"(?i)[a-z][a-z0-9+.-]*://", url):    # absolute server URL -> used as declared (the host is NOT rewritten to the spec's own origin)
            return url.rstrip('/')
        return ((origin.rstrip('/') if origin else "") + "/" + url.lstrip('/')).rstrip('/')   # relative server URL -> resolved against origin
    if spec.get("host"):                                  # Swagger v2 with an explicit host
        schemes = spec.get("schemes")
        scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"
        return "%s://%s%s" % (scheme, spec["host"], basePath.rstrip('/'))
    return (origin.rstrip('/') if origin else "") + basePath.rstrip('/')  # no servers/host -> spec's own origin

_METHODS = ("get", "post", "put", "delete", "patch", "options", "head")

def openApiTargets(content, origin=None, tags=None):
    """
    Returns a list of (url, method, data, headers) request tuples derived from an OpenAPI/Swagger
    specification. 'headers' is a list of (name, value) tuples (matching conf.httpHeaders). 'origin'
    (scheme://host[:port] of the specification's own location) is used only to resolve RELATIVE 'servers'
    entries - absolute server URLs are used as declared. Path parameters and header/cookie values carry
    the custom injection mark so they become testable injection points. 'tags' (list) restricts extraction
    to operations declaring at least one of those OpenAPI tags (to scope a scan of a large API).
    """

    tagSet = set(tags) if tags else None

    spec = _loadSpec(content)
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict) or not spec.get("paths"):
        errMsg = "no valid 'paths' object found in the provided OpenAPI/Swagger specification"
        raise ValueError(errMsg)

    try:
        rootBase = _baseUrl(spec, origin)
    except Exception:                                     # never let base-URL synthesis abort the whole run
        rootBase = origin.rstrip('/') if isinstance(origin, six.string_types) else ""
    isV2 = "swagger" in spec and "openapi" not in spec
    retVal = []
    cache = {}   # $ref -> synthesized example, shared across all operations (large specs reuse schemas)

    for path, item in (spec.get("paths") or {}).items():
        item = _resolve(spec, item)                       # a Path Item object may itself be a $ref
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") or []            # 'or []': a present-but-null 'parameters' must not break concatenation
        for method, operation in item.items():
            if str(method).lower() not in _METHODS or not isinstance(operation, dict):   # str(): YAML keys can be non-string (e.g. 404, 'on'->bool)
                continue
            if tagSet is not None and not (tagSet & set(_ for _ in (operation.get("tags") or []) if isinstance(_, six.string_types))):
                continue                                  # '--openapi-tags' filter: operation carries none of the requested tags
            try:
                # effective base URL with OpenAPI precedence: operation 'servers' > path-item 'servers' > root
                opServers = operation.get("servers") or item.get("servers")
                base = rootBase
                if opServers:
                    try:
                        base = _baseUrl(spec, origin, opServers)
                    except Exception:
                        base = rootBase

                # merge path-level + operation-level parameters, de-duplicated by (in, name); operation wins
                params, seen = [], {}
                for raw in ((shared if isinstance(shared, list) else []) + (operation.get("parameters") or [])):
                    resolved = _resolve(spec, raw)
                    if isinstance(resolved, dict) and resolved.get("name"):
                        key = (resolved.get("in"), resolved.get("name"))
                        if key in seen:
                            params[seen[key]] = resolved
                            continue
                        seen[key] = len(params)
                    params.append(resolved)

                urlPath = path if isinstance(path, six.string_types) else str(path)
                query, headers, form, cookies = [], [], [], []

                for param in params:
                    if not isinstance(param, dict):
                        continue
                    location, name = param.get("in"), param.get("name")
                    if not name:
                        continue
                    if not isinstance(name, six.string_types):   # YAML can yield a non-string param name (e.g. 5)
                        name = str(name)
                    explicit = _explicitExample(spec, param)   # parameter-level example/examples wins over schema synthesis
                    if explicit is not _NO_EXAMPLE:
                        value = _scalar(explicit)
                    else:
                        schema = param.get("schema") or {"type": param.get("type", "string")}
                        value = _scalar(_example(spec, schema, cache=cache))
                    if location == "path":
                        # mark the filled path segment as a (custom) URI injection point - path parameters are
                        # prime REST injection targets; the value is encoded first so its own chars add no mark
                        urlPath = urlPath.replace("{%s}" % name, _urlSafe(value) + CUSTOM_INJECTION_MARK_CHAR)
                    elif location == "query":
                        # best-effort: array/object query params are scalarized (single value), NOT expanded per
                        # OpenAPI style/explode (repeated keys, comma/space/pipe delimited, deepObject) - the goal
                        # is one testable request per operation, not faithful serialization
                        query.append("%s=%s" % (_urlSafe(name, "[]"), _urlSafe(value)))
                    elif location == "header":
                        # append the custom injection mark so the header value becomes a testable (custom)
                        # injection point (non-exclusive: query/body params are still auto-tested); skip names
                        # that are not valid HTTP field-name tokens
                        headerName = _headerClean(name)
                        if headerName and _HEADER_NAME_RE.match(headerName):
                            headers.append((headerName, "%s%s" % (_headerClean(_noMark(value)), CUSTOM_INJECTION_MARK_CHAR)))
                    elif location == "cookie":
                        # a cookie name is a token; the value must not contain cookie-structure chars ('; ,'
                        # and whitespace) or a spec could smuggle extra cookie pairs
                        cookieName = _headerClean(name)
                        if cookieName and _HEADER_NAME_RE.match(cookieName):
                            cookieValue = re.sub(r"[;,\s]", "", _headerClean(_noMark(value)))
                            cookies.append("%s=%s%s" % (cookieName, cookieValue, CUSTOM_INJECTION_MARK_CHAR))
                    elif location == "formData":              # Swagger v2 in:"formData" -> urlencoded body field
                        form.append("%s=%s" % (_urlSafe(name, "[]"), _urlSafe(value)))

                if cookies:                                   # aggregate all cookie params into a single Cookie header
                    headers.append((HTTP_HEADER.COOKIE, "; ".join(cookies)))

                urlPath = urlPath.replace(" ", "%20").replace("?", "%3F").replace("#", "%23")   # keep a literal path key from breaking the URL (filled values are already encoded)
                if urlPath and not urlPath.startswith("/"):   # OpenAPI path keys start with '/'; harden a loose spec so base+path is not glued (/v1pets)
                    urlPath = "/" + urlPath

                url = base + urlPath
                if query:
                    url += "?" + "&".join(query)

                url = re.sub(r"\{[^}]+\}", "1", url)                # any leftover template var (undefined path OR server variable) -> "1"

                if not re.match(r"(?i)[a-z][a-z0-9+.-]*://", url):   # no scheme/host -> unscannable relative URL
                    logger.warning("skipping OpenAPI operation '%s %s' (unable to resolve an absolute target URL; provide the specification by URL or add a 'servers'/'host' entry)" % (str(method).upper(), path))
                    continue

                data = None
                body = _resolve(spec, operation.get("requestBody") or {})
                content_ = body.get("content") if isinstance(body, dict) else None
                if isinstance(content_, dict) and content_:
                    mediaTypes = [_ for _ in content_ if isinstance(_, six.string_types)]   # media-type keys must be strings
                    picked = next((_ for _ in mediaTypes if _ == "application/json" or _.endswith("+json") or "json" in _), None) \
                             or ("application/x-www-form-urlencoded" if "application/x-www-form-urlencoded" in mediaTypes else None) \
                             or (mediaTypes[0] if mediaTypes else None)
                    if picked:
                        mediaType = content_[picked] if isinstance(content_[picked], dict) else {}
                        example = _explicitExample(spec, mediaType)   # media-type-level example/examples wins over schema synthesis
                        if example is _NO_EXAMPLE:
                            example = _example(spec, mediaType.get("schema") or {}, cache=cache)
                        if "json" in picked:
                            data = _noMark(json.dumps(example, default=str))
                            headers.append((HTTP_HEADER.CONTENT_TYPE, "application/json"))
                        elif picked == "application/x-www-form-urlencoded" and isinstance(example, dict):
                            data = "&".join("%s=%s" % (_urlSafe(name, "[]"), _urlSafe(_scalar(value))) for name, value in example.items())
                            headers.append((HTTP_HEADER.CONTENT_TYPE, "application/x-www-form-urlencoded"))
                        elif isinstance(example, six.string_types):
                            # raw (text / xml / ...) body -> mark it so the whole body becomes a testable point
                            data = _noMark(example) + CUSTOM_INJECTION_MARK_CHAR
                            headers.append((HTTP_HEADER.CONTENT_TYPE, picked))
                        else:                              # e.g. multipart/form-data or a structured non-JSON body (no safe serialization)
                            logger.debug("not synthesizing a '%s' request body for '%s %s'" % (picked, str(method).upper(), path))
                elif isinstance(operation.get("parameters"), list) or isV2:
                    for param in params:                   # Swagger v2 in:"body"
                        if isinstance(param, dict) and param.get("in") == "body":
                            example = _example(spec, param.get("schema") or {}, cache=cache)
                            data = _noMark(json.dumps(example, default=str))
                            headers.append((HTTP_HEADER.CONTENT_TYPE, "application/json"))

                if data is None and form:                  # Swagger v2 in:"formData" fields -> urlencoded body
                    data = "&".join(form)
                    headers.append((HTTP_HEADER.CONTENT_TYPE, "application/x-www-form-urlencoded"))

                retVal.append((url, str(method).upper(), data, headers or None))
            except Exception as ex:
                logger.warning("skipping OpenAPI operation '%s %s' (%s)" % (str(method).upper(), path, getSafeExString(ex)))

    return retVal
