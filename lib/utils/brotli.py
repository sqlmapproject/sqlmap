#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Native, dependency-free Brotli (RFC 7932) decompressor, so sqlmap can advertise a browser-realistic
# 'Accept-Encoding: gzip, deflate, br' and read 'Content-Encoding: br' responses (common behind CDNs)
# without pulling in the 'brotli'/'brotlicffi' third-party module. Decode-only: it is used solely to
# inflate server responses (see lib/request/basic.py::decodePage). Validated byte-for-byte against the
# reference encoder across every quality/window/size. The 122 KB static dictionary + context-lookup
# table live ZIP-packed in data/txt/brotli-dictionary.tx_ (same convention as wordlist.tx_). Py 2.7 / 3.x.

import os
import zipfile

_DICTIONARY = None                                         # 122784-byte static dictionary (lazy-loaded)
_CONTEXT = None                                            # 2048-byte context-lookup table (4 modes x 2 halves x 256)

# RFC 7932 Appendix A: words are bucketed by length (4..24); size_bits gives the index width per bucket,
# offsets the cumulative byte offset of each bucket (derived from size_bits; last bucket end == 122784).
_SIZE_BITS = [0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5]
_OFFSETS = [0] * 25
for _i in range(24):
    _OFFSETS[_i + 1] = _OFFSETS[_i] + ((_i << _SIZE_BITS[_i]) if _SIZE_BITS[_i] else 0)

# insert-length and copy-length codes (RFC 7932 section 5): (extra bits, base) per code 0..23
_INS_EXTRA = [0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24]
_INS_BASE = [0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594]
_COPY_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24]
_COPY_BASE = [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118]
# block-length code (RFC 7932 section 6): (extra bits, base) per code 0..25
_BLEN_EXTRA = [2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24]
_BLEN_BASE = [1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433, 16625]

# insert-and-copy command split (RFC 7932 section 5): per command range (code >> 6), the insert/copy
# sub-code base and whether the distance is implicit (codes 0..127 reuse the last distance)
_CMD_RANGE = [(0, 0, True), (0, 8, True), (0, 0, False), (0, 8, False), (8, 0, False), (8, 8, False),
              (0, 16, False), (16, 0, False), (8, 16, False), (16, 8, False), (16, 16, False)]

# code-length-code order and the fixed prefix used to read the 18 code-length code lengths (section 3.5)
_CL_ORDER = [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15]
_CLP_LEN = [2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4]
_CLP_VAL = [0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5]

# distance short codes (RFC 7932 section 4): index into the 4-entry distance ring + a signed delta
_DIST_IDX_OFF = [3, 2, 1, 0, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2]
_DIST_VAL_OFF = [0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3]

# transform table (RFC 7932 Appendix B): (prefix, transform id, suffix); ids 0=identity, 1..9=omit-last-N,
# 10=uppercase-first, 11=uppercase-all, 12..20=omit-first-N
_TRANSFORMS = [
    (b"", 0, b""),
    (b"", 0, b" "),
    (b" ", 0, b" "),
    (b"", 12, b""),
    (b"", 10, b" "),
    (b"", 0, b" the "),
    (b" ", 0, b""),
    (b"s ", 0, b" "),
    (b"", 0, b" of "),
    (b"", 10, b""),
    (b"", 0, b" and "),
    (b"", 13, b""),
    (b"", 1, b""),
    (b", ", 0, b" "),
    (b"", 0, b", "),
    (b" ", 10, b" "),
    (b"", 0, b" in "),
    (b"", 0, b" to "),
    (b"e ", 0, b" "),
    (b"", 0, b"\""),
    (b"", 0, b"."),
    (b"", 0, b"\">"),
    (b"", 0, b"\x0a"),
    (b"", 3, b""),
    (b"", 0, b"]"),
    (b"", 0, b" for "),
    (b"", 14, b""),
    (b"", 2, b""),
    (b"", 0, b" a "),
    (b"", 0, b" that "),
    (b" ", 10, b""),
    (b"", 0, b". "),
    (b".", 0, b""),
    (b" ", 0, b", "),
    (b"", 15, b""),
    (b"", 0, b" with "),
    (b"", 0, b"'"),
    (b"", 0, b" from "),
    (b"", 0, b" by "),
    (b"", 16, b""),
    (b"", 17, b""),
    (b" the ", 0, b""),
    (b"", 4, b""),
    (b"", 0, b". The "),
    (b"", 11, b""),
    (b"", 0, b" on "),
    (b"", 0, b" as "),
    (b"", 0, b" is "),
    (b"", 7, b""),
    (b"", 1, b"ing "),
    (b"", 0, b"\x0a\x09"),
    (b"", 0, b":"),
    (b" ", 0, b". "),
    (b"", 0, b"ed "),
    (b"", 20, b""),
    (b"", 18, b""),
    (b"", 6, b""),
    (b"", 0, b"("),
    (b"", 10, b", "),
    (b"", 8, b""),
    (b"", 0, b" at "),
    (b"", 0, b"ly "),
    (b" the ", 0, b" of "),
    (b"", 5, b""),
    (b"", 9, b""),
    (b" ", 10, b", "),
    (b"", 10, b"\""),
    (b".", 0, b"("),
    (b"", 11, b" "),
    (b"", 10, b"\">"),
    (b"", 0, b"=\""),
    (b" ", 0, b"."),
    (b".com/", 0, b""),
    (b" the ", 0, b" of the "),
    (b"", 10, b"'"),
    (b"", 0, b". This "),
    (b"", 0, b","),
    (b".", 0, b" "),
    (b"", 10, b"("),
    (b"", 10, b"."),
    (b"", 0, b" not "),
    (b" ", 0, b"=\""),
    (b"", 0, b"er "),
    (b" ", 11, b" "),
    (b"", 0, b"al "),
    (b" ", 11, b""),
    (b"", 0, b"='"),
    (b"", 11, b"\""),
    (b"", 10, b". "),
    (b" ", 0, b"("),
    (b"", 0, b"ful "),
    (b" ", 10, b". "),
    (b"", 0, b"ive "),
    (b"", 0, b"less "),
    (b"", 11, b"'"),
    (b"", 0, b"est "),
    (b" ", 10, b"."),
    (b"", 11, b"\">"),
    (b" ", 0, b"='"),
    (b"", 10, b","),
    (b"", 0, b"ize "),
    (b"", 11, b"."),
    (b"\xc2\xa0", 0, b""),
    (b" ", 0, b","),
    (b"", 10, b"=\""),
    (b"", 11, b"=\""),
    (b"", 0, b"ous "),
    (b"", 11, b", "),
    (b"", 10, b"='"),
    (b" ", 10, b","),
    (b" ", 11, b"=\""),
    (b" ", 11, b", "),
    (b"", 11, b","),
    (b"", 11, b"("),
    (b"", 11, b". "),
    (b" ", 11, b"."),
    (b"", 11, b"='"),
    (b" ", 11, b". "),
    (b" ", 10, b"=\""),
    (b" ", 11, b"='"),
    (b" ", 10, b"='"),
]


class BrotliError(Exception):
    pass


def _loadTables():
    global _DICTIONARY, _CONTEXT
    if _DICTIONARY is not None:
        return

    path = None
    try:
        from lib.core.data import paths
        path = getattr(paths, "BROTLI_DICTIONARY", None)
    except ImportError:
        pass
    if not path or not os.path.isfile(path):
        path = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "data", "txt", "brotli-dictionary.tx_")

    archive = zipfile.ZipFile(path)                        # ZIP-packed like wordlist.tx_ / catalog-identifiers.tx_
    try:
        raw = archive.read(archive.namelist()[0])
    finally:
        archive.close()
    if len(raw) != 122784 + 2048:
        raise BrotliError("invalid Brotli dictionary table")
    _DICTIONARY = raw[:122784]
    _CONTEXT = bytearray(raw[122784:])


class _BitReader(object):
    __slots__ = ("data", "size", "pos", "acc", "bits")

    def __init__(self, data):
        self.data = bytearray(data)
        self.size = len(self.data)
        self.pos = 0
        self.acc = 0
        self.bits = 0

    def _fill(self):
        while self.bits <= 24 and self.pos < self.size:
            self.acc |= self.data[self.pos] << self.bits
            self.pos += 1
            self.bits += 8

    def readBits(self, count):
        if count == 0:
            return 0
        if self.bits < count:
            self._fill()
        value = self.acc & ((1 << count) - 1)
        self.acc >>= count
        self.bits -= count
        return value

    def peek(self, count):
        if self.bits < count:
            self._fill()
        return self.acc & ((1 << count) - 1)

    def drop(self, count):
        self.acc >>= count
        self.bits -= count

    def alignToByte(self):
        drop = self.bits & 7
        if drop:
            self.acc >>= drop
            self.bits -= drop

    def readBytes(self, count):
        out = bytearray()
        while count > 0 and self.bits >= 8:
            out.append(self.acc & 0xff)
            self.acc >>= 8
            self.bits -= 8
            count -= 1
        if count > 0:
            out += self.data[self.pos:self.pos + count]
            self.pos += count
        return bytes(out)


def _reverseBits(value, count):
    result = 0
    for _ in range(count):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


class _Huffman(object):
    __slots__ = ("maxLength", "table", "single")

    def __init__(self, lengths):
        self.single = None
        self.table = None
        self.maxLength = max(lengths) if lengths else 0
        if self.maxLength == 0:
            self.single = 0
            for symbol, length in enumerate(lengths):
                if length > 0:
                    self.single = symbol
            return

        counts = [0] * (self.maxLength + 1)
        for length in lengths:
            if length:
                counts[length] += 1
        nextCode = [0] * (self.maxLength + 2)
        code = 0
        for bits in range(1, self.maxLength + 1):
            code = (code + counts[bits - 1]) << 1
            nextCode[bits] = code

        self.table = [(0, 0)] * (1 << self.maxLength)
        for symbol, length in enumerate(lengths):
            if length:
                reversed_ = _reverseBits(nextCode[length], length)
                nextCode[length] += 1
                step = 1 << length
                for index in range(reversed_, 1 << self.maxLength, step):
                    self.table[index] = (symbol, length)

    def decode(self, reader):
        if self.table is None:
            return self.single
        symbol, length = self.table[reader.peek(self.maxLength)]
        reader.drop(length)
        return symbol


def _readSimplePrefix(reader, alphabetSize):
    count = reader.readBits(2) + 1
    symbolBits = (alphabetSize - 1).bit_length() or 1
    symbols = [reader.readBits(symbolBits) for _ in range(count)]
    lengths = [0] * alphabetSize
    if count == 1:
        huffman = _Huffman([])
        huffman.single = symbols[0]
        return huffman
    if count == 2:
        pairs = [(symbols[0], 1), (symbols[1], 1)]
    elif count == 3:
        pairs = [(symbols[0], 1), (symbols[1], 2), (symbols[2], 2)]
    elif reader.readBits(1):
        pairs = [(symbols[0], 1), (symbols[1], 2), (symbols[2], 3), (symbols[3], 3)]
    else:
        pairs = [(symbols[0], 2), (symbols[1], 2), (symbols[2], 2), (symbols[3], 2)]
    for symbol, length in pairs:
        lengths[symbol] = length
    return _Huffman(lengths)


def _readComplexPrefix(reader, alphabetSize, skip):
    codeLengths = [0] * 18
    space = 32
    for symbol in _CL_ORDER[skip:]:
        index = reader.peek(4)
        codeLengths[symbol] = _CLP_VAL[index]
        reader.drop(_CLP_LEN[index])
        if codeLengths[symbol]:
            space -= 32 >> codeLengths[symbol]
        if space <= 0:
            break
    codeLengthHuffman = _Huffman(codeLengths)

    lengths = [0] * alphabetSize
    symbol = 0
    previous = 8
    repeat = 0
    repeatLength = 0
    space = 32768
    while symbol < alphabetSize and space > 0:
        code = codeLengthHuffman.decode(reader)
        if code < 16:
            lengths[symbol] = code
            symbol += 1
            if code:
                previous = code
                space -= 32768 >> code
            repeat = 0
        else:
            extra = 2 if code == 16 else 3
            newLength = previous if code == 16 else 0
            if repeatLength != newLength:
                repeat = 0
                repeatLength = newLength
            old = repeat
            delta = reader.readBits(extra)
            if repeat > 0:
                repeat = (repeat - 2) << extra
            repeat += delta + 3
            emit = repeat - old
            for _ in range(emit):
                if symbol >= alphabetSize:
                    break
                lengths[symbol] = repeatLength
                symbol += 1
            if repeatLength:
                space -= emit << (15 - repeatLength)
    return _Huffman(lengths)


def _readPrefix(reader, alphabetSize):
    header = reader.readBits(2)
    if header == 1:
        return _readSimplePrefix(reader, alphabetSize)
    return _readComplexPrefix(reader, alphabetSize, header)


def _readBlockTypeCount(reader):
    if not reader.readBits(1):
        return 1
    bits = reader.readBits(3)
    return (1 << bits) + 1 + reader.readBits(bits)


def _readContextMap(reader, treeCount, size):
    maxRun = reader.readBits(4) + 1 if reader.readBits(1) else 0
    huffman = _readPrefix(reader, treeCount + maxRun)
    contextMap = []
    while len(contextMap) < size:
        code = huffman.decode(reader)
        if code == 0:
            contextMap.append(0)
        elif code <= maxRun:
            contextMap.extend([0] * ((1 << code) + reader.readBits(code)))
        else:
            contextMap.append(code - maxRun)
    del contextMap[size:]
    if reader.readBits(1):                                 # inverse move-to-front
        moveToFront = list(range(256))
        for i in range(len(contextMap)):
            index = contextMap[i]
            value = moveToFront[index]
            contextMap[i] = value
            del moveToFront[index]
            moveToFront.insert(0, value)
    return contextMap


def _toUpperCase(word, offset):
    char = word[offset]
    if char < 0xc0:                                        # ASCII: flip case of a-z
        if 97 <= char <= 122:
            word[offset] = char ^ 32
        return 1
    if char < 0xe0:                                        # 2-byte UTF-8
        if offset + 1 < len(word):
            word[offset + 1] ^= 32
        return 2
    if offset + 2 < len(word):                             # 3-byte UTF-8
        word[offset + 2] ^= 5
    return 3


def _applyTransform(transformId, word):
    prefix, kind, suffix = _TRANSFORMS[transformId]
    result = bytearray(word)
    if kind == 0:
        pass
    elif 1 <= kind <= 9:                                   # omit last N
        result = result[:len(result) - kind] if len(result) >= kind else bytearray()
    elif 12 <= kind <= 20:                                 # omit first N
        count = kind - 11
        result = result[count:] if len(result) >= count else bytearray()
    elif kind == 10:                                       # uppercase first
        if result:
            _toUpperCase(result, 0)
    elif kind == 11:                                       # uppercase all
        offset = 0
        while offset < len(result):
            offset += _toUpperCase(result, offset)
    return prefix + bytes(result) + suffix


def decompress(data, maxOutput=100 * 1024 * 1024):
    """Decompress a Brotli (RFC 7932) stream, returning the original bytes. Raises BrotliError on a
    malformed stream or if the output would exceed 'maxOutput' (an anti-decompression-bomb cap)."""

    _loadTables()
    dictionary = _DICTIONARY
    context = _CONTEXT

    try:
        reader = _BitReader(data)
        header = reader.readBits(1)
        if header == 0:
            windowBits = 16
        else:
            header = reader.readBits(3)
            if header:
                windowBits = 17 + header
            else:
                header = reader.readBits(3)
                windowBits = (8 + header) if header else 17
        maxBackward = (1 << windowBits) - 16

        out = bytearray()
        distRing = [16, 15, 11, 4]
        distIndex = 0

        while True:
            isLast = reader.readBits(1)
            if isLast and reader.readBits(1):              # ISLASTEMPTY
                break

            nibbles = reader.readBits(2)
            if nibbles == 3:                               # metadata block (no output)
                if reader.readBits(1):
                    raise BrotliError("reserved bit set")
                skipBytes = reader.readBits(2)
                if skipBytes:
                    skipLength = reader.readBits(skipBytes * 8) + 1
                    reader.alignToByte()
                    reader.readBytes(skipLength)
                if isLast:
                    break
                continue

            metaLength = reader.readBits((nibbles + 4) * 4) + 1
            if len(out) + metaLength > maxOutput:          # reject an over-large block up front (anti-bomb)
                raise BrotliError("output too large")
            if not isLast and reader.readBits(1):          # ISUNCOMPRESSED
                reader.alignToByte()
                out += reader.readBytes(metaLength)
                if len(out) > maxOutput:
                    raise BrotliError("output too large")
                continue

            typesL = _readBlockTypeCount(reader)
            blockL, typeHuffmanL, lengthHuffmanL, prevTypeL = 1 << 28, None, None, 1
            typeL = 0
            if typesL >= 2:
                typeHuffmanL = _readPrefix(reader, typesL + 2)
                lengthHuffmanL = _readPrefix(reader, 26)
                code = lengthHuffmanL.decode(reader)
                blockL = _BLEN_BASE[code] + reader.readBits(_BLEN_EXTRA[code])

            typesI = _readBlockTypeCount(reader)
            blockI, typeHuffmanI, lengthHuffmanI, prevTypeI = 1 << 28, None, None, 1
            typeI = 0
            if typesI >= 2:
                typeHuffmanI = _readPrefix(reader, typesI + 2)
                lengthHuffmanI = _readPrefix(reader, 26)
                code = lengthHuffmanI.decode(reader)
                blockI = _BLEN_BASE[code] + reader.readBits(_BLEN_EXTRA[code])

            typesD = _readBlockTypeCount(reader)
            blockD, typeHuffmanD, lengthHuffmanD, prevTypeD = 1 << 28, None, None, 1
            typeD = 0
            if typesD >= 2:
                typeHuffmanD = _readPrefix(reader, typesD + 2)
                lengthHuffmanD = _readPrefix(reader, 26)
                code = lengthHuffmanD.decode(reader)
                blockD = _BLEN_BASE[code] + reader.readBits(_BLEN_EXTRA[code])

            postfix = reader.readBits(2)
            direct = reader.readBits(4) << postfix
            contextModes = [reader.readBits(2) for _ in range(typesL)]

            treesL = _readBlockTypeCount(reader)
            contextMapL = _readContextMap(reader, treesL, typesL * 64) if treesL >= 2 else [0] * (typesL * 64)
            treesD = _readBlockTypeCount(reader)
            contextMapD = _readContextMap(reader, treesD, typesD * 4) if treesD >= 2 else [0] * (typesD * 4)

            huffmanL = [_readPrefix(reader, 256) for _ in range(treesL)]
            huffmanI = [_readPrefix(reader, 704) for _ in range(typesI)]
            distanceAlphabet = 16 + direct + (48 << postfix)
            huffmanD = [_readPrefix(reader, distanceAlphabet) for _ in range(treesD)]

            produced = 0
            while produced < metaLength:
                if blockI == 0:
                    code = typeHuffmanI.decode(reader)
                    nextType = prevTypeI if code == 0 else ((typeI + 1) % typesI if code == 1 else code - 2)
                    prevTypeI, typeI = typeI, nextType
                    code = lengthHuffmanI.decode(reader)
                    blockI = _BLEN_BASE[code] + reader.readBits(_BLEN_EXTRA[code])
                blockI -= 1

                command = huffmanI[typeI].decode(reader)
                insertBase, copyBase, implicit = _CMD_RANGE[command >> 6]
                insertCode = insertBase + ((command >> 3) & 7)
                copyCode = copyBase + (command & 7)
                insertLength = _INS_BASE[insertCode] + reader.readBits(_INS_EXTRA[insertCode])
                copyLength = _COPY_BASE[copyCode] + reader.readBits(_COPY_EXTRA[copyCode])
                # a well-formed command never inserts beyond the meta-block; bounding here keeps a hostile
                # stream from spinning the literal loop far past the output cap before it is caught (the
                # copy length is checked in the back-reference branch, and dictionary copies are <= 24)
                if produced + insertLength > metaLength:
                    raise BrotliError("insert exceeds meta-block length")

                for _ in range(insertLength):
                    if blockL == 0:
                        code = typeHuffmanL.decode(reader)
                        nextType = prevTypeL if code == 0 else ((typeL + 1) % typesL if code == 1 else code - 2)
                        prevTypeL, typeL = typeL, nextType
                        code = lengthHuffmanL.decode(reader)
                        blockL = _BLEN_BASE[code] + reader.readBits(_BLEN_EXTRA[code])
                    blockL -= 1
                    mode = contextModes[typeL] * 512
                    p1 = out[-1] if out else 0
                    p2 = out[-2] if len(out) >= 2 else 0
                    contextId = context[mode + p1] | context[mode + 256 + p2]
                    out.append(huffmanL[contextMapL[64 * typeL + contextId]].decode(reader))
                    produced += 1

                if produced >= metaLength:
                    break

                if implicit:
                    distanceCode = 0
                else:
                    if blockD == 0:
                        code = typeHuffmanD.decode(reader)
                        nextType = prevTypeD if code == 0 else ((typeD + 1) % typesD if code == 1 else code - 2)
                        prevTypeD, typeD = typeD, nextType
                        code = lengthHuffmanD.decode(reader)
                        blockD = _BLEN_BASE[code] + reader.readBits(_BLEN_EXTRA[code])
                    blockD -= 1
                    distanceContext = min(copyLength - 2, 3) if copyLength >= 2 else 0
                    distanceCode = huffmanD[contextMapD[4 * typeD + distanceContext]].decode(reader)

                if distanceCode < 16:
                    distance = distRing[(distIndex + _DIST_IDX_OFF[distanceCode]) & 3] + _DIST_VAL_OFF[distanceCode]
                else:
                    value = distanceCode - 16
                    if value < direct:
                        distance = value + 1
                    else:
                        value -= direct
                        extraBits = 1 + (value >> (postfix + 1))
                        extra = reader.readBits(extraBits)
                        high = value >> postfix
                        low = value & ((1 << postfix) - 1)
                        distance = ((((2 + (high & 1)) << extraBits) - 4 + extra) << postfix) + low + direct + 1

                maxDistance = min(len(out), maxBackward)
                if distanceCode != 0 and distance <= maxDistance:
                    distRing[distIndex & 3] = distance
                    distIndex += 1

                if distance <= maxDistance:               # ordinary back-reference (may overlap)
                    if produced + copyLength > metaLength:  # can't copy past the block (also bounds the loop)
                        raise BrotliError("copy exceeds meta-block length")
                    source = len(out) - distance
                    for i in range(copyLength):
                        out.append(out[source + i])
                        produced += 1
                else:                                      # static-dictionary reference
                    offset = distance - maxDistance - 1
                    if not (4 <= copyLength <= 24) or _SIZE_BITS[copyLength] == 0:
                        raise BrotliError("invalid dictionary reference")
                    bits = _SIZE_BITS[copyLength]
                    index = offset & ((1 << bits) - 1)
                    transformId = offset >> bits
                    if transformId >= len(_TRANSFORMS):
                        raise BrotliError("invalid dictionary transform")
                    start = _OFFSETS[copyLength] + index * copyLength
                    word = _applyTransform(transformId, dictionary[start:start + copyLength])
                    out += word
                    produced += len(word)

                if len(out) > maxOutput:
                    raise BrotliError("output too large")

            if isLast:
                break
        return bytes(out)
    except BrotliError:
        raise
    except Exception as ex:
        raise BrotliError("malformed Brotli stream (%s)" % ex)
