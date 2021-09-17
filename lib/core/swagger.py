#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import json

from lib.core.data import logger
from lib.core.exception import SqlmapSyntaxException

class Operation:

    def __init__(self, op):
        self.op = op

    def tags(self):
        return self.op["tags"]

    def parameters(self):
        return self.op["parameters"]

    def parametersForTypes(self, types):
        return list(filter(lambda p: (p["in"] in types), self.parameters()))

    def bodyRef(self):
        if "requestBody" in self.op:
            return self.op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        return None

    # header injection is not currently supported
    def injectable(self, body):
     return len(self.parametersForTypes(["query", "path"])) > 0 or body

    def queryString(self):
        queryParameters = self.parametersForTypes(["query"])
        if len(queryParameters) < 1:
            return None
        queryString = ""
        for qp in queryParameters:
            queryString += "&%s=%s" %(qp["name"], qp["example"])

        return queryString.replace('&', '', 1)

    def path(self, path):
        pathParameters = self.parametersForTypes(["path"])
        if len(pathParameters) < 1:
            return path
        parameterPath = path
        for p in pathParameters:
            parameterPath = parameterPath.replace("{%s}" %p["name"], "%s*" %p["example"])
        return parameterPath

def _ref(swagger, refPath):
     paths = refPath.replace("#/", "", 1).split('/')
     r = swagger
     for p in paths:
        r = r[p]
     return r

def _example(swagger, refPath):
    example = {}
    ref = _ref(swagger, refPath)
    if "type" in ref and ref["type"] == "object" and "properties" in ref:
        properties = ref["properties"]
        for prop in properties:
            if "example" in properties[prop]:
                value = properties[prop]["example"]
                example[prop] = value
            elif "$ref" in properties[prop]:
                example[prop] = _example(swagger, properties[prop]["$ref"])
            elif properties[prop]["type"] == "array" and "$ref" in properties[prop]["items"]:
                example[prop] =  [ _example(swagger, properties[prop]["items"]["$ref"]) ]

    return example

def parse(content, tags):
    """
    Parses Swagger OpenAPI 3.x.x JSON documents
    """

    try:
        swagger = json.loads(content)

        # extra validations
        if "openapi" not in swagger or not swagger["openapi"].startswith("3."):
          errMsg = "swagger must be OpenAPI 3.x.x!"
          raise SqlmapSyntaxException(errMsg)

        if ("servers" not in swagger or
                not isinstance(swagger["servers"], list) or
                len(swagger["servers"]) < 1 or
                "url" not in swagger["servers"][0]):
          errMsg = "swagger server is missing!"
          raise SqlmapSyntaxException(errMsg)

        server = swagger["servers"][0]["url"]

        logger.info("swagger OpenAPI version '%s', server '%s'" %(swagger["openapi"], server))

        for path in swagger["paths"]:
            for operation in swagger["paths"][path]:
                op = Operation(swagger["paths"][path][operation])

                # skip any operations without one of our tags
                if tags is not None and not any(tag in op.tags() for tag in tags):
                    continue

                body = {}
                bodyRef = op.bodyRef()
                if bodyRef:
                  body = _example(swagger, bodyRef)

                if not op.injectable(body):
                    logger.info("excluding path '%s', operation '%s' as there are no parameters to inject" %(path, operation))
                    continue

                url = None
                method = None
                data = None
                cookie = None

                parameterPath = op.path(path)
                qs = op.queryString()
                url = "%s%s" % (server, parameterPath)
                method = operation.upper()
                if body:
                    data = json.dumps(body)

                if qs is not None:
                    url += "?" + qs

                logger.debug("including url '%s', method '%s', data '%s', cookie '%s'" %(url, method, data, cookie))
                yield (url, method, data, cookie, None)

    except json.decoder.JSONDecodeError:
        errMsg = "swagger file is not valid JSON"
        raise SqlmapSyntaxException(errMsg)
