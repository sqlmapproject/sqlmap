#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import json

from lib.core.data import logger
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapSkipTargetException

class Operation:

    def __init__(self, name, method, props):
        self.name = name
        self.method = method
        self.props = props 

    def tags(self):
        return self.props["tags"]

    def parameters(self):
        return self.props["parameters"]

    def parametersForTypes(self, types):
        return list(filter(lambda p: (p["in"] in types), self.parameters()))

    def bodyRef(self):
        if "requestBody" in self.props:
            return self.props["requestBody"]["content"]["application/json"]["schema"]["$ref"]
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
            if "example" not in qp:
                raise SqlmapSkipTargetException("missing example for parameter '%s'" %qp["name"])
            queryString += "&%s=%s" %(qp["name"], qp["example"])

        return queryString.replace('&', '', 1)

    def path(self, path):
        pathParameters = self.parametersForTypes(["path"])
        if len(pathParameters) < 1:
            return path
        parameterPath = path
        for p in pathParameters:
            if "example" not in p:
                raise SqlmapSkipTargetException("missing example for parameter '%s'" %p["name"])
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
            else:
                raise SqlmapSkipTargetException("missing example for parameter '%s'" %prop)


    return example

def parse(content, tags):
    """
    Parses Swagger OpenAPI 3.x.x JSON documents

    Target injectable parameter values are generated from the "example" properties.
    Only property-level "example" is supported. The "examples" property is not supported.
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
            for method in swagger["paths"][path]:
                op = Operation(path, method, swagger["paths"][path][method])
                method = method.upper()

                # skip any operations without one of our tags
                if tags is not None and not any(tag in op.tags() for tag in tags):
                    continue

                try:
                    body = {}
                    bodyRef = op.bodyRef()
                    if bodyRef:
                      body = _example(swagger, bodyRef)

                    if op.injectable(body):
                        url = None
                        data = None
                        cookie = None

                        parameterPath = op.path(path)
                        qs = op.queryString()
                        url = "%s%s" % (server, parameterPath)
                        if body:
                            data = json.dumps(body)

                        if qs is not None:
                            url += "?" + qs

                        logger.debug("including url '%s', method '%s', data '%s', cookie '%s'" %(url, method, data, cookie))
                        yield (url, method, data, cookie, None)
                    else:
                        logger.info("excluding path '%s', method '%s' as there are no parameters to inject" %(path, method))

                except SqlmapSkipTargetException as e:
                    logger.warn("excluding path '%s', method '%s': %s" %(path, method, e))

    except json.decoder.JSONDecodeError:
        errMsg = "swagger file is not valid JSON"
        raise SqlmapSyntaxException(errMsg)
