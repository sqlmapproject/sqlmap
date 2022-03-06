from xmltodict import parse, ParsingInterrupted
import unittest

try:
    from io import BytesIO as StringIO
except ImportError:
    from xmltodict import StringIO

from xml.parsers.expat import ParserCreate
from xml.parsers import expat


def _encode(s):
    try:
        return bytes(s, 'ascii')
    except (NameError, TypeError):
        return s


class XMLToDictTestCase(unittest.TestCase):

    def test_string_vs_file(self):
        xml = '<a>data</a>'
        self.assertEqual(parse(xml),
                         parse(StringIO(_encode(xml))))

    def test_minimal(self):
        self.assertEqual(parse('<a/>'),
                         {'a': None})
        self.assertEqual(parse('<a/>', force_cdata=True),
                         {'a': None})

    def test_simple(self):
        self.assertEqual(parse('<a>data</a>'),
                         {'a': 'data'})

    def test_force_cdata(self):
        self.assertEqual(parse('<a>data</a>', force_cdata=True),
                         {'a': {'#text': 'data'}})

    def test_custom_cdata(self):
        self.assertEqual(parse('<a>data</a>',
                               force_cdata=True,
                               cdata_key='_CDATA_'),
                         {'a': {'_CDATA_': 'data'}})

    def test_list(self):
        self.assertEqual(parse('<a><b>1</b><b>2</b><b>3</b></a>'),
                         {'a': {'b': ['1', '2', '3']}})

    def test_attrib(self):
        self.assertEqual(parse('<a href="xyz"/>'),
                         {'a': {'@href': 'xyz'}})

    def test_skip_attrib(self):
        self.assertEqual(parse('<a href="xyz"/>', xml_attribs=False),
                         {'a': None})

    def test_custom_attrib(self):
        self.assertEqual(parse('<a href="xyz"/>',
                               attr_prefix='!'),
                         {'a': {'!href': 'xyz'}})

    def test_attrib_and_cdata(self):
        self.assertEqual(parse('<a href="xyz">123</a>'),
                         {'a': {'@href': 'xyz', '#text': '123'}})

    def test_semi_structured(self):
        self.assertEqual(parse('<a>abc<b/>def</a>'),
                         {'a': {'b': None, '#text': 'abcdef'}})
        self.assertEqual(parse('<a>abc<b/>def</a>',
                               cdata_separator='\n'),
                         {'a': {'b': None, '#text': 'abc\ndef'}})

    def test_nested_semi_structured(self):
        self.assertEqual(parse('<a>abc<b>123<c/>456</b>def</a>'),
                         {'a': {'#text': 'abcdef', 'b': {
                             '#text': '123456', 'c': None}}})

    def test_skip_whitespace(self):
        xml = """
        <root>


          <emptya>           </emptya>
          <emptyb attr="attrvalue">


          </emptyb>
          <value>hello</value>
        </root>
        """
        self.assertEqual(
            parse(xml),
            {'root': {'emptya': None,
                      'emptyb': {'@attr': 'attrvalue'},
                      'value': 'hello'}})

    def test_keep_whitespace(self):
        xml = "<root> </root>"
        self.assertEqual(parse(xml), dict(root=None))
        self.assertEqual(parse(xml, strip_whitespace=False),
                         dict(root=' '))

    def test_streaming(self):
        def cb(path, item):
            cb.count += 1
            self.assertEqual(path, [('a', {'x': 'y'}), ('b', None)])
            self.assertEqual(item, str(cb.count))
            return True
        cb.count = 0
        parse('<a x="y"><b>1</b><b>2</b><b>3</b></a>',
              item_depth=2, item_callback=cb)
        self.assertEqual(cb.count, 3)

    def test_streaming_interrupt(self):
        cb = lambda path, item: False
        self.assertRaises(ParsingInterrupted,
                          parse, '<a>x</a>',
                          item_depth=1, item_callback=cb)

    def test_postprocessor(self):
        def postprocessor(path, key, value):
            try:
                return key + ':int', int(value)
            except (ValueError, TypeError):
                return key, value
        self.assertEqual({'a': {'b:int': [1, 2], 'b': 'x'}},
                         parse('<a><b>1</b><b>2</b><b>x</b></a>',
                               postprocessor=postprocessor))

    def test_postprocessor_attribute(self):
        def postprocessor(path, key, value):
            try:
                return key + ':int', int(value)
            except (ValueError, TypeError):
                return key, value
        self.assertEqual({'a': {'@b:int': 1}},
                         parse('<a b="1"/>',
                               postprocessor=postprocessor))

    def test_postprocessor_skip(self):
        def postprocessor(path, key, value):
            if key == 'b':
                value = int(value)
                if value == 3:
                    return None
            return key, value
        self.assertEqual({'a': {'b': [1, 2]}},
                         parse('<a><b>1</b><b>2</b><b>3</b></a>',
                               postprocessor=postprocessor))

    def test_unicode(self):
        try:
            value = unichr(39321)
        except NameError:
            value = chr(39321)
        self.assertEqual({'a': value},
                         parse('<a>%s</a>' % value))

    def test_encoded_string(self):
        try:
            value = unichr(39321)
        except NameError:
            value = chr(39321)
        xml = '<a>%s</a>' % value
        self.assertEqual(parse(xml),
                         parse(xml.encode('utf-8')))

    def test_namespace_support(self):
        xml = """
        <root xmlns="http://defaultns.com/"
              xmlns:a="http://a.com/"
              xmlns:b="http://b.com/">
          <x a:attr="val">1</x>
          <a:y>2</a:y>
          <b:z>3</b:z>
        </root>
        """
        d = {
            'http://defaultns.com/:root': {
                'http://defaultns.com/:x': {
                    '@xmlns': {
                        '': 'http://defaultns.com/',
                        'a': 'http://a.com/',
                        'b': 'http://b.com/',
                    },
                    '@http://a.com/:attr': 'val',
                    '#text': '1',
                },
                'http://a.com/:y': '2',
                'http://b.com/:z': '3',
            }
        }
        res = parse(xml, process_namespaces=True)
        self.assertEqual(res, d)

    def test_namespace_collapse(self):
        xml = """
        <root xmlns="http://defaultns.com/"
              xmlns:a="http://a.com/"
              xmlns:b="http://b.com/">
          <x a:attr="val">1</x>
          <a:y>2</a:y>
          <b:z>3</b:z>
        </root>
        """
        namespaces = {
            'http://defaultns.com/': '',
            'http://a.com/': 'ns_a',
        }
        d = {
            'root': {
                'x': {
                    '@xmlns': {
                        '': 'http://defaultns.com/',
                        'a': 'http://a.com/',
                        'b': 'http://b.com/',
                    },
                    '@ns_a:attr': 'val',
                    '#text': '1',
                },
                'ns_a:y': '2',
                'http://b.com/:z': '3',
            },
        }
        res = parse(xml, process_namespaces=True, namespaces=namespaces)
        self.assertEqual(res, d)

    def test_namespace_ignore(self):
        xml = """
        <root xmlns="http://defaultns.com/"
              xmlns:a="http://a.com/"
              xmlns:b="http://b.com/">
          <x>1</x>
          <a:y>2</a:y>
          <b:z>3</b:z>
        </root>
        """
        d = {
            'root': {
                '@xmlns': 'http://defaultns.com/',
                '@xmlns:a': 'http://a.com/',
                '@xmlns:b': 'http://b.com/',
                'x': '1',
                'a:y': '2',
                'b:z': '3',
            },
        }
        self.assertEqual(parse(xml), d)

    def test_force_list_basic(self):
        xml = """
        <servers>
          <server>
            <name>server1</name>
            <os>os1</os>
          </server>
        </servers>
        """
        expectedResult = {
            'servers': {
                'server': [
                    {
                        'name': 'server1',
                        'os': 'os1',
                    },
                ],
            }
        }
        self.assertEqual(parse(xml, force_list=('server',)), expectedResult)

    def test_force_list_callable(self):
        xml = """
        <config>
            <servers>
              <server>
                <name>server1</name>
                <os>os1</os>
              </server>
            </servers>
            <skip>
                <server></server>
            </skip>
        </config>
        """

        def force_list(path, key, value):
            """Only return True for servers/server, but not for skip/server."""
            if key != 'server':
                return False
            return path and path[-1][0] == 'servers'

        expectedResult = {
            'config': {
                'servers': {
                    'server': [
                        {
                            'name': 'server1',
                            'os': 'os1',
                        },
                    ],
                },
                'skip': {
                    'server': None,
                },
            },
        }
        self.assertEqual(parse(xml, force_list=force_list, dict_constructor=dict), expectedResult)

    def test_disable_entities_true_ignores_xmlbomb(self):
        xml = """
        <!DOCTYPE xmlbomb [
            <!ENTITY a "1234567890" >
            <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">
            <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;">
        ]>
        <bomb>&c;</bomb>
        """
        expectedResult = {'bomb': None}
        try:
            parse_attempt = parse(xml, disable_entities=True)
        except expat.ExpatError:
            self.assertTrue(True)
        else:
            self.assertEqual(parse_attempt, expectedResult)

    def test_disable_entities_false_returns_xmlbomb(self):
        xml = """
        <!DOCTYPE xmlbomb [
            <!ENTITY a "1234567890" >
            <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">
            <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;">
        ]>
        <bomb>&c;</bomb>
        """
        bomb = "1234567890" * 64
        expectedResult = {'bomb': bomb}
        self.assertEqual(parse(xml, disable_entities=False), expectedResult)

    def test_disable_entities_true_ignores_external_dtd(self):
        xml = """
        <!DOCTYPE external [
            <!ENTITY ee SYSTEM "http://www.python.org/">
        ]>
        <root>&ee;</root>
        """
        expectedResult = {'root': None}
        try:
            parse_attempt = parse(xml, disable_entities=True)
        except expat.ExpatError:
            self.assertTrue(True)
        else:
            self.assertEqual(parse_attempt, expectedResult)

    def test_disable_entities_true_attempts_external_dtd(self):
        xml = """
        <!DOCTYPE external [
            <!ENTITY ee SYSTEM "http://www.python.org/">
        ]>
        <root>&ee;</root>
        """

        def raising_external_ref_handler(*args, **kwargs):
            parser = ParserCreate(*args, **kwargs)
            parser.ExternalEntityRefHandler = lambda *x: 0
            try:
                feature = "http://apache.org/xml/features/disallow-doctype-decl"
                parser._reader.setFeature(feature, True)
            except AttributeError:
                pass
            return parser
        expat.ParserCreate = raising_external_ref_handler
        # Using this try/catch because a TypeError is thrown before
        # the ExpatError, and Python 2.6 is confused by that.
        try:
            parse(xml, disable_entities=False, expat=expat)
        except expat.ExpatError:
            self.assertTrue(True)
        else:
            self.assertTrue(False)
        expat.ParserCreate = ParserCreate
