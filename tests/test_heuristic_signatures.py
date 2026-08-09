#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Cross-engine invariants of the non-SQL heuristic signatures in lib/core/settings.py.

heuristicCheckSqlInjection() tries every one of these regexes against the same response and prints a
hint for each one that matches. There is no order and no priority, so a signature that is a little too
generous does not merely lose precision - it makes sqlmap recommend a switch that has nothing to do
with the target. The two ways that happens:

  overlap         one engine claims another engine's error (a stylesheet failure suggesting '--xpath',
                  a Hibernate failure suggesting '--nosql', an XML parser failure suggesting '--xpath').
  false positive  a signature matches a page that is not an error at all - a surname that contains
                  'pug', a <script src=> of the handlebars runtime, a CSS comment holding the words
                  'template' and 'error', or a plain SQL injection error.

The corpus below is real error output, one entry per back-end, labelled with the engine that owns it.
Every engine must recognise its own errors and nothing else.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.settings import GRAPHQL_ERROR_REGEX
from lib.core.settings import HQL_ERROR_REGEX
from lib.core.settings import LDAP_ERROR_REGEX
from lib.core.settings import NOSQL_ERROR_REGEX
from lib.core.settings import SSTI_ERROR_REGEX
from lib.core.settings import XPATH_ERROR_REGEX
from lib.core.settings import XSLT_ERROR_REGEX
from lib.core.settings import XXE_ERROR_REGEX
from lib.core.settings import SPARQL_ERROR_REGEX
from lib.core.settings import ODATA_ERROR_REGEX

ENGINES = (
    ("nosql", NOSQL_ERROR_REGEX),
    ("graphql", GRAPHQL_ERROR_REGEX),
    ("ldap", LDAP_ERROR_REGEX),
    ("xpath", XPATH_ERROR_REGEX),
    ("ssti", SSTI_ERROR_REGEX),
    ("hql", HQL_ERROR_REGEX),
    ("xslt", XSLT_ERROR_REGEX),
    ("xxe", XXE_ERROR_REGEX),
    ("sparql", SPARQL_ERROR_REGEX),
    ("odata", ODATA_ERROR_REGEX),
)

# (owning engine, back-end, verbatim error output). NOBODY means no engine may match it
NOBODY = "-"

CORPUS = (
    ("xpath", "lxml", "lxml.etree.XPathEvalError: Invalid expression"),
    ("xpath", "Java Xalan", "javax.xml.xpath.XPathExpressionException: javax.xml.transform.TransformerException: Extra illegal tokens: ''', 1, ')'"),
    ("xpath", "Saxon", "net.sf.saxon.trans.XPathException: Unexpected token \"'\" at start of expression"),
    ("xpath", ".NET", "System.Xml.XPath.XPathException: 'user/*[' has an invalid token."),
    ("xpath", "PHP DOMXPath", "Warning: DOMXPath::query(): Invalid expression in /var/www/html/search.php on line 22"),
    ("xpath", "PHP SimpleXML", "Warning: SimpleXMLElement::xpath(): Invalid expression in /var/www/html/s.php on line 12"),
    ("xpath", "BaseX", "org.basex.query.QueryException: [XPST0003] Unexpected end of query."),
    ("xpath", "eXist", "org.exist.xquery.XPathException: exerr:ERROR Invalid expression"),
    ("xpath", "libxml2", "xmlXPathEval: evaluation failed"),

    ("xslt", "PHP XSLTProcessor", "Warning: XSLTProcessor::importStylesheet(): compilation error: file /tmp/s.xsl line 3 element value-of"),
    ("xslt", "libxslt parse", "xsltParseStylesheetProcess : document is not a stylesheet"),
    ("xslt", "lxml", "lxml.etree.XSLTParseError: xsl:value-of : could not compile select expression 'foo('"),
    ("xslt", "Saxon", "Static error at char 5 in expression: XTDE0640: Circularity"),
    ("xslt", ".NET", "System.Xml.Xsl.XslLoadException: 'x(' is an invalid XPath expression."),
    ("xslt", "Java Transformer", "javax.xml.transform.TransformerConfigurationException: Could not compile stylesheet"),
    ("xslt", "libxslt runtime", "runtime error: file s.xsl line 4 element value-of\nXPath error : Invalid expression\n"),

    ("xxe", "PHP libxml2", "Warning: simplexml_load_string(): I/O warning : failed to load external entity \"file:///nonexistent\""),
    ("xxe", "Java Xerces", "org.xml.sax.SAXParseException; lineNumber: 1; columnNumber: 10; DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" set to true."),
    ("xxe", "Python expat", "xml.parsers.expat.ExpatError: undefined entity: line 2, column 10"),
    ("xxe", ".NET", "System.Xml.XmlException: Reference to undeclared entity 'xxe'."),
    ("xxe", "Nokogiri", "Nokogiri::XML::SyntaxError: Entity 'xxe' not defined"),
    ("xxe", "Go", "XML syntax error on line 3: unexpected EOF"),

    ("ssti", "Jinja2", "jinja2.exceptions.TemplateSyntaxError: unexpected '}'"),
    ("ssti", "Twig", "Twig\\Error\\SyntaxError: Unknown \"foo\" filter in \"index.twig\" at line 3."),
    ("ssti", "Freemarker", "freemarker.core.ParseException: Encountered \"}\" at line 1, column 14"),
    ("ssti", "Velocity", "org.apache.velocity.exception.ParseErrorException: Encountered '}'"),
    ("ssti", "Spring EL", "org.springframework.expression.spel.SpelEvaluationException: EL1008E: Property or field 'x' cannot be found"),
    ("ssti", "Struts2 OGNL", "ognl.OgnlException: target is null for setProperty(null, \"x\", [Ljava.lang.String;)"),
    ("ssti", "ERB", "(erb):1:in `<main>': undefined local variable or method `x'"),
    ("ssti", "Handlebars", "Error: Parse error on line 1:\n{{#x}}\n-----^\nExpecting 'ID'"),

    ("hql", "Hibernate 5", "org.hibernate.hql.internal.ast.QuerySyntaxException: unexpected token: ' near line 1, column 42"),
    ("hql", "Hibernate 6", "org.hibernate.query.SemanticException: line 1:25 no viable alternative at input 'from User where name='"),
    ("hql", "EclipseLink", "Exception [EclipseLink-8025] : Problem compiling [SELECT u FROM User u WHERE u.name=']"),
    ("hql", "JPA", "jakarta.persistence.PersistenceException: org.hibernate.QueryException: unexpected char"),

    ("nosql", "MongoDB", "MongoServerError: unknown top level operator: $where"),
    ("nosql", "Mongoose", "CastError: Cast to ObjectId failed for value \"x'\" at path \"_id\""),
    ("nosql", "Cassandra", "InvalidRequestException: line 1:23 no viable alternative at input '''"),
    ("nosql", "Cassandra driver", "ResponseError: line 1:38 no viable alternative at input"),
    ("nosql", "Neo4j", "Neo.ClientError.Statement.SyntaxError: Invalid input ''': expected an expression"),
    ("nosql", "Neo4j function", "Neo.ClientError.Statement.SyntaxError: Unknown function 'foo'"),
    ("nosql", "Redis", "WRONGTYPE Operation against a key holding the wrong kind of value"),
    ("nosql", "Elasticsearch", "{\"error\":{\"root_cause\":[{\"type\":\"query_shard_exception\"}]}}"),
    ("nosql", "CouchDB", "{\"error\":\"query_parse_error\",\"reason\":\"Bad special field name\"}"),

    # the quotes arrive backslash-escaped, because the message is a JSON string value
    ("graphql", "graphql-js parse", "{\"errors\":[{\"message\":\"Syntax Error: Expected Name, found <EOF>.\"}]}"),
    ("graphql", "graphql-js validation", "{\"errors\":[{\"message\":\"Cannot query field \\\"foo\\\" on type \\\"Query\\\". Did you mean \\\"food\\\"?\"}]}"),
    ("graphql", "Apollo APQ", "{\"errors\":[{\"message\":\"PersistedQueryNotFound\"}]}"),

    ("ldap", "Java JNDI", "javax.naming.directory.InvalidSearchFilterException: Missing 'equal' in filter"),
    ("ldap", "Active Directory", "LdapErr: DSID-0C0906DC, comment: In order to perform this operation a successful bind must be completed"),
    ("ldap", "OpenLDAP", "ldap_search_ext: Bad search filter (-7)"),
    ("ldap", "python-ldap", "ldap.FILTER_ERROR: {'desc': 'Bad search filter'}"),
    ("ldap", "ApacheDS", "org.apache.directory.api.ldap.model.exception.LdapInvalidSearchFilterException"),

    # Recorded off real back-ends, not written from memory. Each one is the verbatim answer of a
    # deliberately vulnerable front-end to a payload that breaks the syntax of its engine
    ("ssti", "jinja2 (live)", "TemplateSyntaxError: unexpected 'end of template'"),
    ("ssti", "mako (live)", "SyntaxException: Expected: %> at line: 1 char: 7"),
    ("ssti", "twig (live)", "Twig\\Error\\SyntaxError: Unexpected token \"end of template\" of value \"\" in \"__string_template__9bfdeabc\" at line 1."),
    ("ssti", "pug (live)", "Error: Pug:1:11 > 1"),
    ("ssti", "handlebars (live)", "Error: Parse error on line 1: Hello {{ --------^ Expecting 'ID', 'STRING', 'NUMBER', got 'EOF'"),
    ("ssti", "thymeleaf (live)", "org.springframework.expression.ParseException: Expression [Hello ${] @6: No ending suffix '}' for expression starting at character 6: ${"),
    ("ssti", "freemarker (live)", "freemarker.core.ParseException: Syntax error in template \"inj\" in line 1, column 8: Unexpected end of file reached."),
    ("ssti", "velocity (live)", "org.apache.velocity.exception.ParseErrorException: Encountered \"x\" at inj[line 1, column 11] Was expecting one of: \"[\" ... \"{\" ... \"(\""),
    ("ssti", "struts2 (live)", "ognl.ExpressionSyntaxException: Malformed OGNL expression:"),
    ("nosql", "neo4j (live)", "error: Failed to parse string literal. The query must contain an even number of non-escaped quotes. (line 1, column 63 (offset: 62))"),
    ("nosql", "arango (live)", "error: ArangoDB error: \"AQL: syntax error, unexpected ) near ')' RETURN u' at position 1:65 (while parsing)\""),
    ("nosql", "cassandra (live)", "error: line 1:76 mismatched character ' ' expecting '''"),
    ("nosql", "cassandra alt (live)", "error: line 1:60 no viable alternative at input 'OR' (...lab.users WHERE username='' [OR]...)"),
    ("nosql", "elasticsearch (live)", "error: Elasticsearch error: {\"root_cause\":[{\"type\":\"query_shard_exception\",\"reason\":\"Failed to parse query [username:luther]\"}]}"),
    ("nosql", "redis (live)", "error: ERR Error compiling script (new function): user_script:1: unfinished string near ' '"),
    ("nosql", "solr (live)", "error: Solr error: {\"metadata\":[\"error-class\",\"org.apache.solr.common.SolrException\"]}"),
    ("nosql", "dynamodb (live)", "error: Statement wasn't well formed, can't be processed: SELECT * FROM users WHERE username = 'luther' AND password = '''"),
    ("graphql", "graphql (live)", "errors\":[{\"message\":\"Cannot parse query\",\"extensions\":{\"code\":\"GRAPHQL_PARSE_FAILED\"}}]}"),
    ("ldap", "openldap (live)", "errorMessage\":\"Bad search filter (-7): {'result': -7, 'desc': 'Bad search filter', 'errno': 11}"),
    ("xpath", "lxml (live)", "error\":\"XPathEvalError: Invalid expression\"}"),
    ("xpath", "xquery (live)", "error Stopped at /app/, 3/25: [XPST0003] Expecting function argument, found ':'."),
    ("xslt", "libxslt (live)", "XSLT error StartTag: invalid element name, line 4, column 45 ( , line 4)"),
    ("xxe", "libxml2 (live)", "Parsed document; content: Parser warnings: failed to load \"file:///nonexistent\": No such file or directory"),

    ("sparql", "Jena / Fuseki", "org.apache.jena.query.QueryParseException: Encountered \" <VAR1> \"?x\"\" at line 1"),
    ("sparql", "Virtuoso", "Virtuoso 37000 Error SP030: SPARQL compiler, line 1: syntax error at '}'"),
    ("sparql", "RDF4J / GraphDB", "org.eclipse.rdf4j.query.parser.sparql.ast.VisitorException: MalformedQueryException"),
    ("sparql", "Stardog", "com.complexible.stardog.plan.eval.operator.OperatorException: parse error"),
    # captured live off Apache Jena Fuseki with a broken-out string literal
    ("sparql", "Jena (live)", "Parse error: Lexical error at line 1, column 136.  Encountered: <EOF> after prefix"),

    ("odata", "Microsoft OData", "The query specified in the URI is not valid. Syntax error at position 12 in 'Name eq'."),
    ("odata", "Olingo (Java)", "org.apache.olingo.server.api.ODataApplicationException: The URI is malformed"),
    # captured live off ASP.NET Core OData with a broken-out $filter string literal
    ("odata", "Microsoft OData (live)", "The query specified in the URI is not valid. There is an unterminated string literal at position 17 in 'Name eq 'luther'''."),
    ("odata", "Microsoft OData property (live)", "The query specified in the URI is not valid. Could not find a property named 'Xyz' on type 'Default.Product'."),

    # a plain SQL injection error belongs to the SQL engine. No non-SQL switch may claim it
    (NOBODY, "MySQL", "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"),
    (NOBODY, "Microsoft SQL Server", "Incorrect syntax near 'MERGE'."),
    (NOBODY, "Oracle", "ORA-00933: SQL command not properly ended"),
    (NOBODY, "PostgreSQL", "ERROR:  unterminated quoted string at or near \"'\""),
    (NOBODY, "SQLite", "sqlite3.OperationalError: unrecognized token: \"'\""),
    (NOBODY, "Trino", "io.trino.sql.parser.ParsingException: line 1:15: mismatched input 'FROM'. Expecting: '(', <query>"),

    # ordinary pages and unrelated tool output
    (NOBODY, "gcc", "main.c:5:9: error: expected ';' before '}' token"),
    (NOBODY, "python re", "re.error: bad character range a-Z at position 4"),
    (NOBODY, "java date", "java.text.ParseException: Unparseable date: \"2026-13-45\""),
    (NOBODY, "TypeScript", "error TS2448: Block-scoped variable 'x' must be declared before it is used."),
    (NOBODY, "surname", "<td>Contact: Mrs. Puget</td><td>Sales</td>"),
    (NOBODY, "asset (pug)", "<script src=\"/static/js/pug-runtime.min.js\"></script>"),
    (NOBODY, "asset (handlebars)", "<script src=\"/assets/handlebars.runtime-v4.7.7.js\"></script>"),
    (NOBODY, "colour name", "<option value=\"jade\">Jade green</option>"),
    (NOBODY, "error page", "<h1>500 Internal Server Error</h1><p>The server encountered an internal error.</p>"),
    (NOBODY, "CSS comment", "/* template error state: .alert{color:red} */"),
    (NOBODY, "documentation", "This page explains how to use a query exception handler in your application."),
    (NOBODY, "calculator", "Invalid expression: 2++2"),
)

# The only overlaps that are allowed, because the error text really does belong to both. libxslt and
# .NET report the failure of an XPath expression that sits inside a stylesheet, so both switches are
# worth trying - which is what the response says. Anything else is a bug in the signatures.
ACCEPTED_SHARED = {
    ("xslt", ".NET"): ("xpath",),
    ("xslt", "libxslt runtime"): ("xpath",),
    # breaking a stylesheet also breaks the XML that carries it, so libxml2 reports a malformed
    # document as well. Harmless: the XXE hint needs an XML/SOAP request body to fire at all
    ("xslt", "libxslt (live)"): ("xxe",),
}


def _matches(text):
    return tuple(name for name, regex in ENGINES if re.search(regex, text))


class HeuristicSignatureTest(unittest.TestCase):
    def test_each_engine_recognises_its_own_errors(self):
        for owner, backend, text in CORPUS:
            if owner == NOBODY:
                continue
            self.assertIn(owner, _matches(text),
                          msg="'--%s' no longer recognises its own %s error: %r" % (owner, backend, text))

    def test_no_engine_claims_another_engines_error(self):
        for owner, backend, text in CORPUS:
            if owner == NOBODY:
                continue
            allowed = ACCEPTED_SHARED.get((owner, backend), ())
            stolen = [_ for _ in _matches(text) if _ != owner and _ not in allowed]
            self.assertEqual(stolen, [],
                             msg="a %s %s error also suggests %s" % (owner, backend, '/'.join("'--%s'" % _ for _ in stolen)))

    def test_nothing_fires_on_sql_errors_or_ordinary_pages(self):
        for owner, backend, text in CORPUS:
            if owner != NOBODY:
                continue
            fired = _matches(text)
            self.assertEqual(fired, (),
                             msg="%s output suggests %s: %r" % (backend, '/'.join("'--%s'" % _ for _ in fired), text))

    def test_every_engine_is_covered(self):
        # a new switch must arrive here with its own errors, or the matrix above proves nothing about it
        owners = set(owner for owner, _, _ in CORPUS)
        missing = set(name for name, _ in ENGINES) - owners
        self.assertEqual(missing, set(), msg="engines with no corpus entry: %s" % missing)


if __name__ == "__main__":
    unittest.main(verbosity=2)
