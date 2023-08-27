#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import json

from lib.core.data import logger
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapSkipTargetException
from typing import Dict

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
        # OpenAPI v3
        if "requestBody" in self.props:
            return self.props["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        # swagger v2
        elif "parameters" in self.props:
            inParameters = self.parametersForTypes(["body"])
            if not isinstance(inParameters, list) or len(inParameters) < 1:
                return None
            return inParameters[0]["schema"]["$ref"]
        return None

    # header injection is not currently supported
    def injectable(self, body):
     return len(self.parametersForTypes(["query", "path", "header"])) > 0 or body

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

    def headers(self):
        hdrs = []
        headerParameters = self.parametersForTypes(["header"])
        if len(headerParameters) < 1:
            return hdrs
        for hp in headerParameters:
            if "example" not in hp:
                raise SqlmapSkipTargetException("missing example for header '%s'" %hp["name"])
            hdrs.append((hp["name"], "%s*" %hp["example"]))
        return hdrs

def _obj(swagger, objOrRefPath):
     if isinstance(objOrRefPath, Dict):
         return objOrRefPath
     paths = objOrRefPath.replace("#/", "", 1).split('/')
     r = swagger
     for p in paths:
        r = r[p]
     return r

def _example(swagger, objOrRefPath):
    example = {}
    obj = _obj(swagger, objOrRefPath)

    if "type" in obj and obj["type"] == "object" and "properties" in obj:
        properties = obj["properties"]
        for prop in properties:
            if properties[prop]["type"] == "object":
                example[prop] = {}
                for objectProp in properties[prop]["properties"]:
                  example[prop][objectProp] = _example(swagger, properties[prop]["properties"][objectProp])
            elif "$ref" in properties[prop]:
                example[prop] = _example(swagger, properties[prop]["$ref"])
            elif properties[prop]["type"] == "array" and "$ref" in properties[prop]["items"]:
                example[prop] =  [ _example(swagger, properties[prop]["items"]["$ref"]) ]
            elif "example" in properties[prop]:
                value = properties[prop]["example"]
                example[prop] = value
            else:
                raise SqlmapSkipTargetException("missing example for parameter '%s'" %prop)
    elif "example" in obj:
        return obj["example"]
    else:
        raise SqlmapSkipTargetException("missing example for object '%s'" %obj)


    return example

def parse(content, tags):
    """
    Parses Swagger 2.x and OpenAPI 3.x.x JSON documents

    Target injectable parameter values are generated from the "example" properties.
    Only property-level "example" is supported. The "examples" property is not supported.
    """

    try:
        swagger = json.loads(content)

        openapiv3 = False
        swaggerv2 = False

        # extra validations
        if "openapi" in swagger and swagger["openapi"].startswith("3."):
            openapiv3 = True

        if "swagger" in swagger and swagger["swagger"].startswith("2."):
            swaggerv2 = True

        if not (openapiv3 or swaggerv2):
            errMsg = "swagger must be either Swagger 2.x or OpenAPI 3.x.x!"
            raise SqlmapSyntaxException(errMsg)

        if (openapiv3 and
               ("servers" not in swagger or
                not isinstance(swagger["servers"], list) or
                len(swagger["servers"]) < 1 or
                "url" not in swagger["servers"][0])):
          errMsg = "swagger server is missing!"
          raise SqlmapSyntaxException(errMsg)

        if swaggerv2 and "host" not in swagger:
          errMsg = "swagger server is missing!"
          raise SqlmapSyntaxException(errMsg)

        if openapiv3:
           # only one server supported
           server = swagger["servers"][0]["url"]

           logger.info("swagger OpenAPI version '%s', server '%s'" %(swagger["openapi"], server))
        elif swaggerv2:
           logger.info("swagger version '%s'" %swagger["swagger"])

           basePath = ""
           if "basePath" in swagger:
               basePath = swagger["basePath"]

           scheme = "https"
           if ("schemes" in swagger and
                   isinstance(swagger["schemes"], list) and
                   len(swagger["schemes"]) > 0):
               scheme = swagger["schemes"][0]

           server = "%s://%s%s" % (scheme, swagger["host"], basePath)

           logger.info("swagger version '%s', server '%s'" %(swagger["swagger"], server))


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
                        headers = op.headers()
                        qs = op.queryString()
                        url = "%s%s" % (server, parameterPath)
                        if body:
                            data = json.dumps(body)

                        if qs is not None:
                            url += "?" + qs

                        logger.debug("including url '%s', method '%s', data '%s', cookie '%s'" %(url, method, data, cookie))
                        yield (url, method, data, cookie, tuple(headers))
                    else:
                        logger.info("excluding path '%s', method '%s' as there are no parameters to inject" %(path, method))

                except SqlmapSkipTargetException as e:
                    logger.warn("excluding path '%s', method '%s': %s" %(path, method, e))

    except json.decoder.JSONDecodeError:
        errMsg = "swagger file is not valid JSON"
        raise SqlmapSyntaxException(errMsg)
