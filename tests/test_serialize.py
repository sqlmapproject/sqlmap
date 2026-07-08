#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Exhaustive lock on the safe (JSON-based, no code execution) serializer that backs the
session store (HashDB) and BigArray disk chunks - the replacement for the former
code-executing serializer.

Two properties must hold forever, on BOTH Python 2.7 and 3.x:

  1. CORRECTNESS - every value sqlmap actually persists must round-trip losslessly, with
     its exact type. The historically fragile cases are covered explicitly: integer/tuple
     dict keys (naive JSON turns them into strings), tuple-vs-list, set/frozenset, bytes,
     the AttribDict/InjectionDict/RawPair classes and their internal state, and the native
     DB-driver scalars (Decimal/datetime/...) that '-d' direct-mode output can contain.
     A regression here silently corrupts a user's saved session.

  2. SECURITY - deserialization must NEVER execute code and must reconstruct ONLY the small
     explicit class allowlist. Any other class name (os.system, subprocess.Popen, eval,
     lib.core.common.shellExec, ...) must be refused with a "forbidden" ValueError, and a
     crafted legacy payload must fail inertly (no side effects).

Kept deliberately verbose - each case maps to a real session/BigArray value or a real report.
"""

import datetime
import decimal
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.bigarray import BigArray
from lib.core.convert import deserializeValue, encodeBase64, getUnicode, serializeValue
from lib.core.convert import _SERIALIZE_TAG
from lib.core.datatype import AttribDict, InjectionDict, LRUDict
from lib.utils.har import RawPair
from thirdparty import six

INTS = six.integer_types
_unichr = six.unichr


def rt(value):
    """Full session round-trip: value -> JSON text -> value."""
    return deserializeValue(serializeValue(value))


def _import_all_modules():
    """Import every sqlmap module (like --smoke-test) so class-subclass reflection sees them all."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for base in ("lib", "plugins", "tamper"):
        for dirpath, _, filenames in os.walk(os.path.join(root, base)):
            if any(skip in dirpath for skip in ("thirdparty", "extra", "tests", "__pycache__")):
                continue
            for filename in filenames:
                if filename.endswith(".py") and filename not in ("__init__.py", "gui.py"):
                    dotted = os.path.join(dirpath, filename[:-3]).replace(root + os.sep, "").replace(os.sep, ".")
                    try:
                        __import__(dotted)
                    except Exception:
                        pass   # import health is --smoke-test's job; here we only need the classes that DO load


def _all_subclasses(cls):
    for sub in cls.__subclasses__():
        yield sub
        for _ in _all_subclasses(sub):
            yield _


class TestScalars(unittest.TestCase):
    def test_simple(self):
        for value in [None, True, False, 0, 1, -1, 42, 3.14, -0.5, 0.0]:
            restored = rt(value)
            self.assertEqual(restored, value)
            self.assertIs(type(restored) is bool, type(value) is bool)   # bool never collapses to int

    def test_big_ints(self):
        for value in [2 ** 64, 2 ** 200, -(2 ** 128)]:
            self.assertEqual(rt(value), value)

    def test_text(self):
        # empty, ascii, non-BMP, sqlmap's reversible-codec private-use-area char, control chars
        for value in [u"", u"plain", _unichr(0x2299) + u" mid " + _unichr(0xFF),
                      _unichr(0x1F600) if sys.maxunicode > 0xFFFF else u"x",
                      _unichr(0xF0055), u"tab\tnewline\nquote\"backslash\\"]:
            restored = rt(value)
            self.assertEqual(restored, value)
            self.assertIsInstance(restored, six.text_type)


class TestBinary(unittest.TestCase):
    def test_bytes(self):
        for value in [b"", b"abc", b"\x00\x01\x02\xff\xfe", bytes(bytearray(range(256)))]:
            restored = rt(value)
            self.assertEqual(restored, value)
            self.assertIsInstance(restored, bytes)

    def test_bytearray(self):
        value = bytearray(b"\x00binary\xff")
        restored = rt(value)
        self.assertEqual(restored, value)
        self.assertIsInstance(restored, bytearray)

    def test_memoryview(self):
        # some drivers (e.g. psycopg2 on py3) return memoryview for BLOB columns
        restored = rt(memoryview(b"\x00\x01blob"))
        self.assertEqual(bytes(restored) if isinstance(restored, (bytearray, memoryview)) else restored, b"\x00\x01blob")


class TestContainers(unittest.TestCase):
    def test_list_nested(self):
        value = [1, [2, [3, [4]]], "x", None]
        self.assertEqual(rt(value), value)

    def test_tuple_preserved(self):
        for value in [(), (1,), (1, 2, "x"), ((1, 2), (3,))]:
            restored = rt(value)
            self.assertEqual(restored, value)
            self.assertIsInstance(restored, tuple)                 # must NOT degrade to list

    def test_tuple_not_confused_with_list(self):
        restored = rt([(1, 2), [1, 2]])
        self.assertIsInstance(restored[0], tuple)
        self.assertIsInstance(restored[1], list)

    def test_set_and_frozenset(self):
        for value in [set(), {1, 2, 3}, {u"a", u"b"}]:
            restored = rt(value)
            self.assertEqual(restored, value)
            self.assertIsInstance(restored, set)
        fs = frozenset([1, 2])
        restored = rt(fs)
        self.assertEqual(restored, fs)
        self.assertIsInstance(restored, frozenset)


class TestDicts(unittest.TestCase):
    def test_string_keys(self):
        value = {u"a": 1, u"b": {u"c": [1, 2]}}
        self.assertEqual(rt(value), value)

    def test_int_keys_preserved(self):
        # THE landmine: naive json.dumps turns {1: ...} into {"1": ...}; injection.data is int-keyed
        restored = rt({1: u"one", 2: u"two", 100: u"hundred"})
        self.assertEqual(restored, {1: u"one", 2: u"two", 100: u"hundred"})
        self.assertTrue(all(isinstance(k, INTS) for k in restored), list(restored))

    def test_tuple_and_mixed_keys(self):
        value = {(1, 2): u"tuple-key", u"s": 1, 7: u"int-key"}
        restored = rt(value)
        self.assertEqual(restored, value)
        self.assertIn((1, 2), restored)
        self.assertTrue(any(isinstance(k, INTS) and not isinstance(k, bool) for k in restored))

    def test_empty_dict(self):
        self.assertEqual(rt({}), {})


class TestSqlmapTypes(unittest.TestCase):
    def test_attribdict(self):
        value = AttribDict()
        value.foo = u"bar"
        value["n"] = {u"k": [1, (2, 3)]}
        restored = rt(value)
        self.assertIsInstance(restored, AttribDict)
        self.assertEqual(restored.foo, u"bar")
        self.assertEqual(restored["n"], {u"k": [1, (2, 3)]})

    def test_attribdict_keycheck_flag_preserved(self):
        strict = AttribDict(keycheck=True)
        lax = AttribDict(keycheck=False)
        self.assertTrue(rt(strict).__dict__.get("_keycheck"))
        self.assertFalse(rt(lax).__dict__.get("_keycheck"))
        # a lax AttribDict returns None for a missing attribute instead of raising - behaviour must survive
        self.assertIsNone(rt(lax).nonexistent_attribute)

    def test_injectiondict_full(self):
        inj = InjectionDict()
        inj.place = "GET"
        inj.parameter = "id"
        inj.ptype = 1
        inj.prefix = ""
        inj.suffix = ""
        inj.dbms = "MySQL"
        inj.notes = ["note1"]
        # int-keyed .data (PAYLOAD.TECHNIQUE.* are ints), each a nested AttribDict
        for stype in (1, 5):
            data = AttribDict()
            data.title = "technique %d" % stype
            data.payload = u"id=1 AND %d=%d" % (stype, stype)
            data.where = 1
            data.vector = None
            data.matchRatio = 0.987
            data.trueCode = 200
            data.falseCode = 500
            inj.data[stype] = data
        inj.conf = AttribDict()
        inj.conf.textOnly = False

        restored = rt([inj])[0]
        self.assertIsInstance(restored, InjectionDict)
        self.assertEqual(restored.place, "GET")
        self.assertEqual(restored.parameter, "id")
        self.assertEqual(restored.notes, ["note1"])
        self.assertEqual(set(restored.data.keys()), set((1, 5)))
        self.assertTrue(all(isinstance(k, INTS) for k in restored.data), list(restored.data))
        self.assertIsInstance(restored.data[1], AttribDict)
        self.assertEqual(restored.data[1].title, "technique 1")
        self.assertEqual(restored.data[1].matchRatio, 0.987)
        self.assertIsNone(restored.data[1].vector)
        self.assertIsInstance(restored.conf, AttribDict)
        self.assertFalse(restored.conf.textOnly)

    def test_bigarray_type_preserved(self):
        # BigArray is a list subclass; it must round-trip AS a BigArray, not degrade to a plain list
        restored = rt(BigArray([1, 2, (3, 4), u"x"]))
        self.assertIsInstance(restored, BigArray)
        self.assertEqual(list(restored), [1, 2, (3, 4), u"x"])

    def test_rawpair(self):
        # the class stored in a BigArray by the HAR collector
        pair = RawPair(b"GET / HTTP/1.1", b"HTTP/1.1 200 OK", startTime=1.5, endTime=2.5, extendedArguments={u"k": u"v"})
        restored = rt(pair)
        self.assertIsInstance(restored, RawPair)
        self.assertEqual(restored.request, b"GET / HTTP/1.1")
        self.assertEqual(restored.response, b"HTTP/1.1 200 OK")
        self.assertEqual(restored.startTime, 1.5)
        self.assertEqual(restored.extendedArguments, {u"k": u"v"})


class TestDbmsScalars(unittest.TestCase):
    # '-d' direct-mode query output (and dump BigArray) can hold native driver types
    def test_decimal(self):
        for value in [decimal.Decimal("0"), decimal.Decimal("1.50"), decimal.Decimal("-0.0001"), decimal.Decimal("123456789.987654321")]:
            restored = rt(value)
            self.assertEqual(restored, value)
            self.assertIsInstance(restored, decimal.Decimal)

    def test_datetime_family(self):
        cases = [
            datetime.datetime(2024, 1, 2, 3, 4, 5, 6),
            datetime.datetime(1970, 1, 1, 0, 0, 0),
            datetime.date(1999, 12, 31),
            datetime.time(23, 59, 58, 123456),
            datetime.timedelta(days=3, seconds=7, microseconds=9),
            datetime.timedelta(0),
        ]
        for value in cases:
            restored = rt(value)
            self.assertEqual(restored, value)
            self.assertIs(type(restored), type(value))


class TestRealSessionObjects(unittest.TestCase):
    # the exact shapes written with serialize=True across the codebase
    def test_brute_tables_columns(self):
        tables = [("mydb", "users"), ("mydb", "logs")]
        columns = [("mydb", "users", "id", "numeric"), ("mydb", "users", "name", "non-numeric")]
        self.assertEqual(rt(tables), tables)
        self.assertEqual(rt(columns), columns)
        self.assertTrue(all(isinstance(_, tuple) for _ in rt(tables)))

    def test_dynamic_markings(self):
        markings = [(u"<b>", None), (None, u"</div>"), (u"pre", u"suf")]
        self.assertEqual(rt(markings), markings)
        self.assertTrue(all(isinstance(_, tuple) for _ in rt(markings)))

    def test_abs_file_paths_set(self):
        paths = set([u"/var/www/index.php", u"/etc/passwd"])
        restored = rt(paths)
        self.assertEqual(restored, paths)
        self.assertIsInstance(restored, set)   # resume code does an explicit isinstance(_, set) union

    def test_kb_chars_attribdict(self):
        chars = AttribDict()
        chars.delimiter = u"abcdef"
        chars.start = u"//start//"
        chars.stop = u"//stop//"
        restored = rt(chars)
        self.assertIsInstance(restored, AttribDict)
        self.assertEqual(restored.delimiter, u"abcdef")


class TestSecurity(unittest.TestCase):
    def _forged(self, class_name):
        # the raw on-wire object wrapper as a hostile session file would hold it (a plain JSON
        # object tag; NOT produced via the encoder, which would re-tag a dict as a harmless map)
        return json.dumps({_SERIALIZE_TAG: "o", "c": class_name, "s": {}})

    def test_forbidden_classes_rejected(self):
        for name in ("os.system", "subprocess.Popen", "builtins.eval", "__builtin__.eval",
                     "lib.core.common.shellExec", "lib.core.common.evaluateCode", "lib.core.common.openFile"):
            try:
                deserializeValue(self._forged(name))
                self.fail("class %r was NOT rejected" % name)
            except ValueError as ex:
                self.assertIn("forbidden", str(ex), msg="unexpected error for %r: %s" % (name, ex))

    def test_legacy_payload_fails_inertly(self):
        # an OLD session stored base64-of-pickle as TEXT; the new text reader must fail on it
        # WITHOUT executing anything (and, in practice, the bumped HASHDB_MILESTONE_VALUE means such
        # a value is never even looked up). Use a classic protocol-0 os.system pickle as the payload.
        sentinel = os.path.join(tempfile.gettempdir(), "sqlmap_serialize_sentinel_%d" % os.getpid())
        if os.path.exists(sentinel):
            os.remove(sentinel)
        legacy_pickle = b"cos\nsystem\n(S'touch " + sentinel.encode("ascii", "ignore") + b"'\ntR."
        legacy_stored = encodeBase64(legacy_pickle, binary=False)   # exactly what old sqlmap wrote
        try:
            deserializeValue(legacy_stored)                         # base64 blob is not valid JSON -> raises
        except Exception:
            pass   # any failure is fine; the point is no execution
        self.assertFalse(os.path.exists(sentinel), "legacy payload EXECUTED (sentinel created)")

    def test_hashdb_ignores_undecodable_old_value(self):
        # the belt-and-suspenders guarantee: even if an un-deserializable (e.g. legacy) value IS
        # looked up, HashDB.retrieve() swallows it and returns None - a stale session never crashes
        from lib.utils.hashdb import HashDB

        handle, path = tempfile.mkstemp(suffix=".sqlite")
        os.close(handle)
        os.remove(path)
        try:
            db = HashDB(path)
            db.write("legacy", encodeBase64(b"cos\nsystem\n(S'x'\ntR.", binary=False))  # stored, NOT serialized
            db.flush()
            db._write_cache.clear()
            db._read_cache.cache.clear()
            self.assertIsNone(db.retrieve("legacy", unserialize=True))   # must be None, not an exception
            db.closeAll()
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_sqlmap_type_not_in_allowlist_fails_loud(self):
        # a sqlmap-own class that is not allowlisted must raise on SERIALIZE (dev-visible), never be
        # silently dropped - LRUDict lives in lib.* and is not serializable
        self.assertRaises(TypeError, serializeValue, LRUDict(capacity=2))

    def test_foreign_exotic_value_degrades_to_text(self):
        # a non-sqlmap, non-handled scalar degrades to its textual form rather than crashing a session
        self.assertEqual(rt(complex(1, 2)), getUnicode(complex(1, 2)))


class TestBigArrayDisk(unittest.TestCase):
    def test_scalar_chunks_through_disk(self):
        ba = BigArray(chunk_size=1)   # force one chunk per item -> exercises the on-disk path
        source = []
        for i in range(300):
            row = (i, u"name%d" % i, decimal.Decimal("%d.25" % i), None, b"\x00\xff")
            source.append(row)
            ba.append(row)
        self.assertGreater(len(ba.chunks), 1)
        self.assertEqual(len(ba), 300)
        self.assertEqual(list(ba), source)
        self.assertEqual(ba[150], source[150])
        self.assertEqual(ba[-1], source[-1])

    def test_rawpair_chunks_through_disk(self):
        ba = BigArray(chunk_size=1)
        for i in range(40):
            ba.append(RawPair(b"REQ%d" % i, b"RESP%d" % i, startTime=float(i), endTime=float(i) + 1, extendedArguments={u"i": i}))
        got = list(ba)
        self.assertEqual(len(got), 40)
        self.assertTrue(all(isinstance(_, RawPair) for _ in got))
        self.assertEqual(got[7].request, b"REQ7")
        self.assertEqual(got[7].extendedArguments, {u"i": 7})


class TestAllowlistGuard(unittest.TestCase):
    """CI guard: catch a NEW class becoming serializable before it reaches a user's session."""

    def test_allowlist_names_resolve_and_stay_in_sync(self):
        # every allowlisted name must resolve to a class whose real module.qualname matches - keeps
        # convert._SERIALIZE_CLASSES and convert._serializeResolveClass in lockstep (a rename/move/
        # typo of an allowlisted class fails here instead of silently at a user's session load)
        from lib.core.convert import _SERIALIZE_CLASSES, _serializeResolveClass
        for name in _SERIALIZE_CLASSES:
            cls = _serializeResolveClass(name)
            self.assertEqual("%s.%s" % (cls.__module__, cls.__name__), name)

    def test_no_undeclared_attribdict_subclass(self):
        # AttribDict/InjectionDict carry the session's structured data. A NEW AttribDict subclass that
        # ends up stored in the session would be REJECTED by the serializer at a user's runtime. Catch
        # it here coverage-INDEPENDENTLY: import the whole tree, then require every AttribDict subclass
        # to be declared serializable in convert._SERIALIZE_CLASSES.
        from lib.core.convert import _SERIALIZE_CLASSES
        from lib.core.datatype import AttribDict

        _import_all_modules()

        offenders = sorted(set(
            "%s.%s" % (cls.__module__, cls.__name__)
            for cls in _all_subclasses(AttribDict)
        ) - set(_SERIALIZE_CLASSES))

        self.assertEqual(offenders, [], (
            "undeclared AttribDict subclass(es): %s -- if stored in the session, add it to BOTH "
            "convert._SERIALIZE_CLASSES and convert._serializeResolveClass (else the safe serializer "
            "raises on it at a user's runtime). If it is a runtime-only registry, make it subclass a "
            "plain dict instead of AttribDict (see lib.core.unescaper.Unescaper) so it never lands "
            "here." % offenders
        ))

    def test_known_serializable_classes_present(self):
        # lock the intended set: exactly the dict-like data types plus the HAR RawPair. If this list
        # legitimately grows, update it here deliberately (a conscious review point).
        from lib.core.convert import _SERIALIZE_CLASSES
        self.assertEqual(set(_SERIALIZE_CLASSES), set((
            "lib.core.datatype.AttribDict",
            "lib.core.datatype.InjectionDict",
            "lib.utils.har.RawPair",
        )))


class TestHashDBIntegration(unittest.TestCase):
    def test_write_retrieve_roundtrip(self):
        from lib.utils.hashdb import HashDB

        handle, path = tempfile.mkstemp(suffix=".sqlite")
        os.close(handle)
        os.remove(path)
        try:
            inj = InjectionDict()
            inj.place = "GET"
            inj.parameter = "id"
            inj.data[1] = AttribDict()
            inj.data[1].title = "boolean-based blind"
            inj.data[1].matchRatio = 0.9
            value = [inj]

            db = HashDB(path)
            db.write("KB_INJECTIONS", value, serialize=True)
            db.flush()
            # drop the in-memory caches so retrieve() must SELECT the serialized blob back off
            # disk and deserialize it (the real resume path), rather than returning a cached object
            db._write_cache.clear()
            db._read_cache.cache.clear()
            restored = db.retrieve("KB_INJECTIONS", unserialize=True)
            db.closeAll()

            self.assertIsInstance(restored, list)
            self.assertIsInstance(restored[0], InjectionDict)
            self.assertEqual(restored[0].place, "GET")
            self.assertTrue(all(isinstance(k, INTS) for k in restored[0].data))
            self.assertEqual(restored[0].data[1].title, "boolean-based blind")
            self.assertEqual(restored[0].data[1].matchRatio, 0.9)
        finally:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
