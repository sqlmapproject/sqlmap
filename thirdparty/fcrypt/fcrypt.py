# fcrypt.py

"""Unix crypt(3) password hash algorithm.

This is a port to Python of the standard Unix password crypt function.
It's a single self-contained source file that works with any version
of Python from version 1.5 or higher.  The code is based on Eric
Young's optimised crypt in C.

Python fcrypt is intended for users whose Python installation has not
had the crypt module enabled, or whose C library doesn't include the
crypt function.  See the documentation for the Python crypt module for
more information:

  http://www.python.org/doc/current/lib/module-crypt.html

An alternative Python crypt module that uses the MD5 algorithm and is
more secure than fcrypt is available from michal j wallace at:

  http://www.sabren.net/code/python/crypt/index.php3

The crypt() function is a one-way hash function, intended to hide a
password such that the only way to find out the original password is
to guess values until you get a match.  If you need to encrypt and
decrypt data, this is not the module for you.

There are at least two packages providing Python cryptography support:
M2Crypto at <http://www.pobox.org.sg/home/ngps/m2/>, and amkCrypto at
<http://www.amk.ca/python/code/crypto.html>.

Functions:

  crypt() -- return hashed password
"""

__author__ = 'Carey Evans <careye@spamcop.net>'
__version__ = '1.3.1'
__date__ = '21 February 2004'
__credits__ = '''michal j wallace for inspiring me to write this.
Eric Young for the C code this module was copied from.'''

__all__ = ['crypt']


# Copyright (C) 2000, 2001, 2004  Carey Evans  <careye@spamcop.net>
#
# Permission to use, copy, modify, and distribute this software and
# its documentation for any purpose and without fee is hereby granted,
# provided that the above copyright notice appear in all copies and
# that both that copyright notice and this permission notice appear in
# supporting documentation.
#
# CAREY EVANS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
# INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
# EVENT SHALL CAREY EVANS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
# USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# Based on C code by Eric Young (eay@mincom.oz.au), which has the
# following copyright.  Especially note condition 3, which imposes
# extra restrictions on top of the standard Python license used above.
#
# The fcrypt.c source is available from:
#     ftp://ftp.psy.uq.oz.au/pub/Crypto/DES/

# ----- BEGIN fcrypt.c LICENSE -----
#
# This library is free for commercial and non-commercial use as long as
# the following conditions are aheared to.  The following conditions
# apply to all code found in this distribution, be it the RC4, RSA,
# lhash, DES, etc., code; not just the SSL code.  The SSL documentation
# included with this distribution is covered by the same copyright terms
# except that the holder is Tim Hudson (tjh@mincom.oz.au).
# 
# Copyright remains Eric Young's, and as such any Copyright notices in
# the code are not to be removed.
# If this package is used in a product, Eric Young should be given attribution
# as the author of the parts of the library used.
# This can be in the form of a textual message at program startup or
# in documentation (online or textual) provided with the package.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#    "This product includes cryptographic software written by
#     Eric Young (eay@mincom.oz.au)"
#    The word 'cryptographic' can be left out if the rouines from the library
#    being used are not cryptographic related :-).
# 4. If you include any Windows specific code (or a derivative thereof) from 
#    the apps directory (application code) you must include an acknowledgement:
#    "This product includes software written by Tim Hudson (tjh@mincom.oz.au)"
# 
# THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# 
# The licence and distribution terms for any publically available version or
# derivative of this code cannot be changed.  i.e. this code cannot simply be
# copied and put under another distribution licence
# [including the GNU Public Licence.]
#
# ----- END fcrypt.c LICENSE -----


import string, struct


_ITERATIONS = 16

_SPtrans = (
    # nibble 0
    [ 0x00820200, 0x00020000, 0x80800000, 0x80820200,
      0x00800000, 0x80020200, 0x80020000, 0x80800000,
      0x80020200, 0x00820200, 0x00820000, 0x80000200,
      0x80800200, 0x00800000, 0x00000000, 0x80020000,
      0x00020000, 0x80000000, 0x00800200, 0x00020200,
      0x80820200, 0x00820000, 0x80000200, 0x00800200,
      0x80000000, 0x00000200, 0x00020200, 0x80820000,
      0x00000200, 0x80800200, 0x80820000, 0x00000000,
      0x00000000, 0x80820200, 0x00800200, 0x80020000,
      0x00820200, 0x00020000, 0x80000200, 0x00800200,
      0x80820000, 0x00000200, 0x00020200, 0x80800000,
      0x80020200, 0x80000000, 0x80800000, 0x00820000,
      0x80820200, 0x00020200, 0x00820000, 0x80800200,
      0x00800000, 0x80000200, 0x80020000, 0x00000000,
      0x00020000, 0x00800000, 0x80800200, 0x00820200,
      0x80000000, 0x80820000, 0x00000200, 0x80020200 ],

    # nibble 1
    [ 0x10042004, 0x00000000, 0x00042000, 0x10040000,
      0x10000004, 0x00002004, 0x10002000, 0x00042000,
      0x00002000, 0x10040004, 0x00000004, 0x10002000,
      0x00040004, 0x10042000, 0x10040000, 0x00000004,
      0x00040000, 0x10002004, 0x10040004, 0x00002000,
      0x00042004, 0x10000000, 0x00000000, 0x00040004,
      0x10002004, 0x00042004, 0x10042000, 0x10000004,
      0x10000000, 0x00040000, 0x00002004, 0x10042004,
      0x00040004, 0x10042000, 0x10002000, 0x00042004,
      0x10042004, 0x00040004, 0x10000004, 0x00000000,
      0x10000000, 0x00002004, 0x00040000, 0x10040004,
      0x00002000, 0x10000000, 0x00042004, 0x10002004,
      0x10042000, 0x00002000, 0x00000000, 0x10000004,
      0x00000004, 0x10042004, 0x00042000, 0x10040000,
      0x10040004, 0x00040000, 0x00002004, 0x10002000,
      0x10002004, 0x00000004, 0x10040000, 0x00042000 ],

    # nibble 2
    [ 0x41000000, 0x01010040, 0x00000040, 0x41000040,
      0x40010000, 0x01000000, 0x41000040, 0x00010040,
      0x01000040, 0x00010000, 0x01010000, 0x40000000,
      0x41010040, 0x40000040, 0x40000000, 0x41010000,
      0x00000000, 0x40010000, 0x01010040, 0x00000040,
      0x40000040, 0x41010040, 0x00010000, 0x41000000,
      0x41010000, 0x01000040, 0x40010040, 0x01010000,
      0x00010040, 0x00000000, 0x01000000, 0x40010040,
      0x01010040, 0x00000040, 0x40000000, 0x00010000,
      0x40000040, 0x40010000, 0x01010000, 0x41000040,
      0x00000000, 0x01010040, 0x00010040, 0x41010000,
      0x40010000, 0x01000000, 0x41010040, 0x40000000,
      0x40010040, 0x41000000, 0x01000000, 0x41010040,
      0x00010000, 0x01000040, 0x41000040, 0x00010040,
      0x01000040, 0x00000000, 0x41010000, 0x40000040,
      0x41000000, 0x40010040, 0x00000040, 0x01010000 ],

    # nibble 3
    [ 0x00100402, 0x04000400, 0x00000002, 0x04100402,
      0x00000000, 0x04100000, 0x04000402, 0x00100002,
      0x04100400, 0x04000002, 0x04000000, 0x00000402,
      0x04000002, 0x00100402, 0x00100000, 0x04000000,
      0x04100002, 0x00100400, 0x00000400, 0x00000002,
      0x00100400, 0x04000402, 0x04100000, 0x00000400,
      0x00000402, 0x00000000, 0x00100002, 0x04100400,
      0x04000400, 0x04100002, 0x04100402, 0x00100000,
      0x04100002, 0x00000402, 0x00100000, 0x04000002,
      0x00100400, 0x04000400, 0x00000002, 0x04100000,
      0x04000402, 0x00000000, 0x00000400, 0x00100002,
      0x00000000, 0x04100002, 0x04100400, 0x00000400,
      0x04000000, 0x04100402, 0x00100402, 0x00100000,
      0x04100402, 0x00000002, 0x04000400, 0x00100402,
      0x00100002, 0x00100400, 0x04100000, 0x04000402,
      0x00000402, 0x04000000, 0x04000002, 0x04100400 ],

    # nibble 4
    [ 0x02000000, 0x00004000, 0x00000100, 0x02004108,
      0x02004008, 0x02000100, 0x00004108, 0x02004000,
      0x00004000, 0x00000008, 0x02000008, 0x00004100,
      0x02000108, 0x02004008, 0x02004100, 0x00000000,
      0x00004100, 0x02000000, 0x00004008, 0x00000108,
      0x02000100, 0x00004108, 0x00000000, 0x02000008,
      0x00000008, 0x02000108, 0x02004108, 0x00004008,
      0x02004000, 0x00000100, 0x00000108, 0x02004100,
      0x02004100, 0x02000108, 0x00004008, 0x02004000,
      0x00004000, 0x00000008, 0x02000008, 0x02000100,
      0x02000000, 0x00004100, 0x02004108, 0x00000000,
      0x00004108, 0x02000000, 0x00000100, 0x00004008,
      0x02000108, 0x00000100, 0x00000000, 0x02004108,
      0x02004008, 0x02004100, 0x00000108, 0x00004000,
      0x00004100, 0x02004008, 0x02000100, 0x00000108,
      0x00000008, 0x00004108, 0x02004000, 0x02000008 ],

    # nibble 5
    [ 0x20000010, 0x00080010, 0x00000000, 0x20080800,
      0x00080010, 0x00000800, 0x20000810, 0x00080000,
      0x00000810, 0x20080810, 0x00080800, 0x20000000,
      0x20000800, 0x20000010, 0x20080000, 0x00080810,
      0x00080000, 0x20000810, 0x20080010, 0x00000000,
      0x00000800, 0x00000010, 0x20080800, 0x20080010,
      0x20080810, 0x20080000, 0x20000000, 0x00000810,
      0x00000010, 0x00080800, 0x00080810, 0x20000800,
      0x00000810, 0x20000000, 0x20000800, 0x00080810,
      0x20080800, 0x00080010, 0x00000000, 0x20000800,
      0x20000000, 0x00000800, 0x20080010, 0x00080000,
      0x00080010, 0x20080810, 0x00080800, 0x00000010,
      0x20080810, 0x00080800, 0x00080000, 0x20000810,
      0x20000010, 0x20080000, 0x00080810, 0x00000000,
      0x00000800, 0x20000010, 0x20000810, 0x20080800,
      0x20080000, 0x00000810, 0x00000010, 0x20080010 ],

    # nibble 6
    [ 0x00001000, 0x00000080, 0x00400080, 0x00400001,
      0x00401081, 0x00001001, 0x00001080, 0x00000000,
      0x00400000, 0x00400081, 0x00000081, 0x00401000,
      0x00000001, 0x00401080, 0x00401000, 0x00000081,
      0x00400081, 0x00001000, 0x00001001, 0x00401081,
      0x00000000, 0x00400080, 0x00400001, 0x00001080,
      0x00401001, 0x00001081, 0x00401080, 0x00000001,
      0x00001081, 0x00401001, 0x00000080, 0x00400000,
      0x00001081, 0x00401000, 0x00401001, 0x00000081,
      0x00001000, 0x00000080, 0x00400000, 0x00401001,
      0x00400081, 0x00001081, 0x00001080, 0x00000000,
      0x00000080, 0x00400001, 0x00000001, 0x00400080,
      0x00000000, 0x00400081, 0x00400080, 0x00001080,
      0x00000081, 0x00001000, 0x00401081, 0x00400000,
      0x00401080, 0x00000001, 0x00001001, 0x00401081,
      0x00400001, 0x00401080, 0x00401000, 0x00001001 ],

    # nibble 7
    [ 0x08200020, 0x08208000, 0x00008020, 0x00000000,
      0x08008000, 0x00200020, 0x08200000, 0x08208020,
      0x00000020, 0x08000000, 0x00208000, 0x00008020,
      0x00208020, 0x08008020, 0x08000020, 0x08200000,
      0x00008000, 0x00208020, 0x00200020, 0x08008000,
      0x08208020, 0x08000020, 0x00000000, 0x00208000,
      0x08000000, 0x00200000, 0x08008020, 0x08200020,
      0x00200000, 0x00008000, 0x08208000, 0x00000020,
      0x00200000, 0x00008000, 0x08000020, 0x08208020,
      0x00008020, 0x08000000, 0x00000000, 0x00208000,
      0x08200020, 0x08008020, 0x08008000, 0x00200020,
      0x08208000, 0x00000020, 0x00200020, 0x08008000,
      0x08208020, 0x00200000, 0x08200000, 0x08000020,
      0x00208000, 0x00008020, 0x08008020, 0x08200000,
      0x00000020, 0x08208000, 0x00208020, 0x00000000,
      0x08000000, 0x08200020, 0x00008000, 0x00208020 ] )

_skb = (
    # for C bits (numbered as per FIPS 46) 1 2 3 4 5 6
    [ 0x00000000, 0x00000010, 0x20000000, 0x20000010,
      0x00010000, 0x00010010, 0x20010000, 0x20010010,
      0x00000800, 0x00000810, 0x20000800, 0x20000810,
      0x00010800, 0x00010810, 0x20010800, 0x20010810,
      0x00000020, 0x00000030, 0x20000020, 0x20000030,
      0x00010020, 0x00010030, 0x20010020, 0x20010030,
      0x00000820, 0x00000830, 0x20000820, 0x20000830,
      0x00010820, 0x00010830, 0x20010820, 0x20010830,
      0x00080000, 0x00080010, 0x20080000, 0x20080010,
      0x00090000, 0x00090010, 0x20090000, 0x20090010,
      0x00080800, 0x00080810, 0x20080800, 0x20080810,
      0x00090800, 0x00090810, 0x20090800, 0x20090810,
      0x00080020, 0x00080030, 0x20080020, 0x20080030,
      0x00090020, 0x00090030, 0x20090020, 0x20090030,
      0x00080820, 0x00080830, 0x20080820, 0x20080830,
      0x00090820, 0x00090830, 0x20090820, 0x20090830 ],

    # for C bits (numbered as per FIPS 46) 7 8 10 11 12 13
    [ 0x00000000, 0x02000000, 0x00002000, 0x02002000,
      0x00200000, 0x02200000, 0x00202000, 0x02202000,
      0x00000004, 0x02000004, 0x00002004, 0x02002004,
      0x00200004, 0x02200004, 0x00202004, 0x02202004,
      0x00000400, 0x02000400, 0x00002400, 0x02002400,
      0x00200400, 0x02200400, 0x00202400, 0x02202400,
      0x00000404, 0x02000404, 0x00002404, 0x02002404,
      0x00200404, 0x02200404, 0x00202404, 0x02202404,
      0x10000000, 0x12000000, 0x10002000, 0x12002000,
      0x10200000, 0x12200000, 0x10202000, 0x12202000,
      0x10000004, 0x12000004, 0x10002004, 0x12002004,
      0x10200004, 0x12200004, 0x10202004, 0x12202004,
      0x10000400, 0x12000400, 0x10002400, 0x12002400,
      0x10200400, 0x12200400, 0x10202400, 0x12202400,
      0x10000404, 0x12000404, 0x10002404, 0x12002404,
      0x10200404, 0x12200404, 0x10202404, 0x12202404 ],

    # for C bits (numbered as per FIPS 46) 14 15 16 17 19 20
    [ 0x00000000, 0x00000001, 0x00040000, 0x00040001,
      0x01000000, 0x01000001, 0x01040000, 0x01040001,
      0x00000002, 0x00000003, 0x00040002, 0x00040003,
      0x01000002, 0x01000003, 0x01040002, 0x01040003,
      0x00000200, 0x00000201, 0x00040200, 0x00040201,
      0x01000200, 0x01000201, 0x01040200, 0x01040201,
      0x00000202, 0x00000203, 0x00040202, 0x00040203,
      0x01000202, 0x01000203, 0x01040202, 0x01040203,
      0x08000000, 0x08000001, 0x08040000, 0x08040001,
      0x09000000, 0x09000001, 0x09040000, 0x09040001,
      0x08000002, 0x08000003, 0x08040002, 0x08040003,
      0x09000002, 0x09000003, 0x09040002, 0x09040003,
      0x08000200, 0x08000201, 0x08040200, 0x08040201,
      0x09000200, 0x09000201, 0x09040200, 0x09040201,
      0x08000202, 0x08000203, 0x08040202, 0x08040203,
      0x09000202, 0x09000203, 0x09040202, 0x09040203 ],

    # for C bits (numbered as per FIPS 46) 21 23 24 26 27 28
    [ 0x00000000, 0x00100000, 0x00000100, 0x00100100,
      0x00000008, 0x00100008, 0x00000108, 0x00100108,
      0x00001000, 0x00101000, 0x00001100, 0x00101100,
      0x00001008, 0x00101008, 0x00001108, 0x00101108,
      0x04000000, 0x04100000, 0x04000100, 0x04100100,
      0x04000008, 0x04100008, 0x04000108, 0x04100108,
      0x04001000, 0x04101000, 0x04001100, 0x04101100,
      0x04001008, 0x04101008, 0x04001108, 0x04101108,
      0x00020000, 0x00120000, 0x00020100, 0x00120100,
      0x00020008, 0x00120008, 0x00020108, 0x00120108,
      0x00021000, 0x00121000, 0x00021100, 0x00121100,
      0x00021008, 0x00121008, 0x00021108, 0x00121108,
      0x04020000, 0x04120000, 0x04020100, 0x04120100,
      0x04020008, 0x04120008, 0x04020108, 0x04120108,
      0x04021000, 0x04121000, 0x04021100, 0x04121100,
      0x04021008, 0x04121008, 0x04021108, 0x04121108 ],

    # for D bits (numbered as per FIPS 46) 1 2 3 4 5 6
    [ 0x00000000, 0x10000000, 0x00010000, 0x10010000,
      0x00000004, 0x10000004, 0x00010004, 0x10010004,
      0x20000000, 0x30000000, 0x20010000, 0x30010000,
      0x20000004, 0x30000004, 0x20010004, 0x30010004,
      0x00100000, 0x10100000, 0x00110000, 0x10110000,
      0x00100004, 0x10100004, 0x00110004, 0x10110004,
      0x20100000, 0x30100000, 0x20110000, 0x30110000,
      0x20100004, 0x30100004, 0x20110004, 0x30110004,
      0x00001000, 0x10001000, 0x00011000, 0x10011000,
      0x00001004, 0x10001004, 0x00011004, 0x10011004,
      0x20001000, 0x30001000, 0x20011000, 0x30011000,
      0x20001004, 0x30001004, 0x20011004, 0x30011004,
      0x00101000, 0x10101000, 0x00111000, 0x10111000,
      0x00101004, 0x10101004, 0x00111004, 0x10111004,
      0x20101000, 0x30101000, 0x20111000, 0x30111000,
      0x20101004, 0x30101004, 0x20111004, 0x30111004 ],

    # for D bits (numbered as per FIPS 46) 8 9 11 12 13 14
    [ 0x00000000, 0x08000000, 0x00000008, 0x08000008,
      0x00000400, 0x08000400, 0x00000408, 0x08000408,
      0x00020000, 0x08020000, 0x00020008, 0x08020008,
      0x00020400, 0x08020400, 0x00020408, 0x08020408,
      0x00000001, 0x08000001, 0x00000009, 0x08000009,
      0x00000401, 0x08000401, 0x00000409, 0x08000409,
      0x00020001, 0x08020001, 0x00020009, 0x08020009,
      0x00020401, 0x08020401, 0x00020409, 0x08020409,
      0x02000000, 0x0A000000, 0x02000008, 0x0A000008,
      0x02000400, 0x0A000400, 0x02000408, 0x0A000408,
      0x02020000, 0x0A020000, 0x02020008, 0x0A020008,
      0x02020400, 0x0A020400, 0x02020408, 0x0A020408,
      0x02000001, 0x0A000001, 0x02000009, 0x0A000009,
      0x02000401, 0x0A000401, 0x02000409, 0x0A000409,
      0x02020001, 0x0A020001, 0x02020009, 0x0A020009,
      0x02020401, 0x0A020401, 0x02020409, 0x0A020409 ],

    # for D bits (numbered as per FIPS 46) 16 17 18 19 20 21
    [ 0x00000000, 0x00000100, 0x00080000, 0x00080100,
      0x01000000, 0x01000100, 0x01080000, 0x01080100,
      0x00000010, 0x00000110, 0x00080010, 0x00080110,
      0x01000010, 0x01000110, 0x01080010, 0x01080110,
      0x00200000, 0x00200100, 0x00280000, 0x00280100,
      0x01200000, 0x01200100, 0x01280000, 0x01280100,
      0x00200010, 0x00200110, 0x00280010, 0x00280110,
      0x01200010, 0x01200110, 0x01280010, 0x01280110,
      0x00000200, 0x00000300, 0x00080200, 0x00080300,
      0x01000200, 0x01000300, 0x01080200, 0x01080300,
      0x00000210, 0x00000310, 0x00080210, 0x00080310,
      0x01000210, 0x01000310, 0x01080210, 0x01080310,
      0x00200200, 0x00200300, 0x00280200, 0x00280300,
      0x01200200, 0x01200300, 0x01280200, 0x01280300,
      0x00200210, 0x00200310, 0x00280210, 0x00280310,
      0x01200210, 0x01200310, 0x01280210, 0x01280310 ],

    # for D bits (numbered as per FIPS 46) 22 23 24 25 27 28
    [ 0x00000000, 0x04000000, 0x00040000, 0x04040000,
      0x00000002, 0x04000002, 0x00040002, 0x04040002,
      0x00002000, 0x04002000, 0x00042000, 0x04042000,
      0x00002002, 0x04002002, 0x00042002, 0x04042002,
      0x00000020, 0x04000020, 0x00040020, 0x04040020,
      0x00000022, 0x04000022, 0x00040022, 0x04040022,
      0x00002020, 0x04002020, 0x00042020, 0x04042020,
      0x00002022, 0x04002022, 0x00042022, 0x04042022,
      0x00000800, 0x04000800, 0x00040800, 0x04040800,
      0x00000802, 0x04000802, 0x00040802, 0x04040802,
      0x00002800, 0x04002800, 0x00042800, 0x04042800,
      0x00002802, 0x04002802, 0x00042802, 0x04042802,
      0x00000820, 0x04000820, 0x00040820, 0x04040820,
      0x00000822, 0x04000822, 0x00040822, 0x04040822,
      0x00002820, 0x04002820, 0x00042820, 0x04042820,
      0x00002822, 0x04002822, 0x00042822, 0x04042822 ] )

_shifts2 = (0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0)

_con_salt = [
    0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,
    0xDA,0xDB,0xDC,0xDD,0xDE,0xDF,0xE0,0xE1,
    0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,
    0xEA,0xEB,0xEC,0xED,0xEE,0xEF,0xF0,0xF1,
    0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,
    0xFA,0xFB,0xFC,0xFD,0xFE,0xFF,0x00,0x01,
    0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
    0x0A,0x0B,0x05,0x06,0x07,0x08,0x09,0x0A,
    0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,
    0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,
    0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,
    0x23,0x24,0x25,0x20,0x21,0x22,0x23,0x24,
    0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,
    0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,
    0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,
    0x3D,0x3E,0x3F,0x40,0x41,0x42,0x43,0x44 ]

_cov_2char = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


def _HPERM_OP(a):
    """Clever bit manipulation."""
    t = ((a << 18) ^ a) & 0xcccc0000
    return a ^ t ^ ((t >> 18) & 0x3fff)

def _PERM_OP(a,b,n,m):
    """Cleverer bit manipulation."""
    t = ((a >> n) ^ b) & m
    b = b ^ t
    a = a ^ (t << n)
    return a,b


def _set_key(password):
    """Generate DES key schedule from ASCII password."""

    c,d = struct.unpack('<ii', password)
    c = (c & 0x7f7f7f7f) << 1
    d = (d & 0x7f7f7f7f) << 1

    d,c = _PERM_OP(d,c,4,0x0f0f0f0f)
    c = _HPERM_OP(c)
    d = _HPERM_OP(d)
    d,c = _PERM_OP(d,c,1,0x55555555)
    c,d = _PERM_OP(c,d,8,0x00ff00ff)
    d,c = _PERM_OP(d,c,1,0x55555555)

    # Any sign-extended bits are masked off.
    d = (((d & 0x000000ff) << 16) | (d & 0x0000ff00) |
         ((d & 0x00ff0000) >> 16) | ((c >> 4) & 0x0f000000))
    c = c & 0x0fffffff

    # Copy globals into local variables for loop.
    shifts2 = _shifts2
    skbc0, skbc1, skbc2, skbc3, skbd0, skbd1, skbd2, skbd3 = _skb

    k = [0] * (_ITERATIONS * 2)

    for i in xrange(_ITERATIONS):
        # Only operates on top 28 bits.
        if shifts2[i]:
            c = (c >> 2) | (c << 26)
            d = (d >> 2) | (d << 26)
        else:
            c = (c >> 1) | (c << 27)
            d = (d >> 1) | (d << 27)
        c = c & 0x0fffffff
        d = d & 0x0fffffff

        s = ( skbc0[  c      & 0x3f                    ] |
              skbc1[((c>> 6) & 0x03) | ((c>> 7) & 0x3c)] |
              skbc2[((c>>13) & 0x0f) | ((c>>14) & 0x30)] |
              skbc3[((c>>20) & 0x01) |
                    ((c>>21) & 0x06) | ((c>>22) & 0x38)] )

        t = ( skbd0[  d      & 0x3f                    ] |
              skbd1[((d>> 7) & 0x03) | ((d>> 8) & 0x3c)] |
              skbd2[((d>>15) & 0x3f)                   ] |
              skbd3[((d>>21) & 0x0f) | ((d>>22) & 0x30)] )

        k[2*i] = ((t << 16) | (s & 0x0000ffff)) & 0xffffffff
        s = (s >> 16) | (t & 0xffff0000)

        # Top bit of s may be 1.
        s = (s << 4) | ((s >> 28) & 0x0f)
        k[2*i + 1] = s & 0xffffffff

    return k


def _body(ks, E0, E1):
    """Use the key schedule ks and salt E0, E1 to create the password hash."""

    # Copy global variable into locals for loop.
    SP0, SP1, SP2, SP3, SP4, SP5, SP6, SP7 = _SPtrans

    inner = xrange(0, _ITERATIONS*2, 2)
    l = r = 0
    for j in xrange(25):
        l,r = r,l
        for i in inner:
            t = r ^ ((r >> 16) & 0xffff)
            u = t & E0
            t = t & E1
            u = u ^ (u << 16) ^ r ^ ks[i]
            t = t ^ (t << 16) ^ r ^ ks[i+1]
            t = ((t >> 4) & 0x0fffffff) | (t << 28)

            l,r = r,(SP1[(t    ) & 0x3f] ^ SP3[(t>> 8) & 0x3f] ^
                     SP5[(t>>16) & 0x3f] ^ SP7[(t>>24) & 0x3f] ^
                     SP0[(u    ) & 0x3f] ^ SP2[(u>> 8) & 0x3f] ^
                     SP4[(u>>16) & 0x3f] ^ SP6[(u>>24) & 0x3f] ^ l)

    l = ((l >> 1) & 0x7fffffff) | ((l & 0x1) << 31)
    r = ((r >> 1) & 0x7fffffff) | ((r & 0x1) << 31)

    r,l = _PERM_OP(r, l,  1, 0x55555555)
    l,r = _PERM_OP(l, r,  8, 0x00ff00ff)
    r,l = _PERM_OP(r, l,  2, 0x33333333)
    l,r = _PERM_OP(l, r, 16, 0x0000ffff)
    r,l = _PERM_OP(r, l,  4, 0x0f0f0f0f)

    return l,r


def crypt(password, salt):
    """Generate an encrypted hash from the passed password.  If the password
is longer than eight characters, only the first eight will be used.

The first two characters of the salt are used to modify the encryption
algorithm used to generate in the hash in one of 4096 different ways.
The characters for the salt should be upper- and lower-case letters A
to Z, digits 0 to 9, '.' and '/'.

The returned hash begins with the two characters of the salt, and
should be passed as the salt to verify the password.

Example:

  >>> from fcrypt import crypt
  >>> password = 'AlOtBsOl'
  >>> salt = 'cE'
  >>> hash = crypt(password, salt)
  >>> hash
  'cEpWz5IUCShqM'
  >>> crypt(password, hash) == hash
  1
  >>> crypt('IaLaIoK', hash) == hash
  0

In practice, you would read the password using something like the
getpass module, and generate the salt randomly:

  >>> import random, string
  >>> saltchars = string.letters + string.digits + './'
  >>> salt = random.choice(saltchars) + random.choice(saltchars)

Note that other ASCII characters are accepted in the salt, but the
results may not be the same as other versions of crypt.  In
particular, '_', '$1' and '$2' do not select alternative hash
algorithms such as the extended passwords, MD5 crypt and Blowfish
crypt supported by the OpenBSD C library.
"""

    # Extract the salt.
    if len(salt) == 0:
        salt = 'AA'
    elif len(salt) == 1:
        salt = salt + 'A'
    Eswap0 = _con_salt[ord(salt[0]) & 0x7f]
    Eswap1 = _con_salt[ord(salt[1]) & 0x7f] << 4

    # Generate the key and use it to apply the encryption.
    ks = _set_key((password + '\0\0\0\0\0\0\0\0')[:8])
    o1, o2 = _body(ks, Eswap0, Eswap1)

    # Extract 24-bit subsets of result with bytes reversed.
    t1 = (o1 << 16 & 0xff0000) | (o1 & 0xff00) | (o1 >> 16 & 0xff)
    t2 = (o1 >> 8 & 0xff0000) | (o2 << 8 & 0xff00) | (o2 >> 8 & 0xff)
    t3 = (o2 & 0xff0000) | (o2 >> 16 & 0xff00)
    # Extract 6-bit subsets.
    r = [ t1 >> 18 & 0x3f, t1 >> 12 & 0x3f, t1 >> 6 & 0x3f, t1 & 0x3f,
          t2 >> 18 & 0x3f, t2 >> 12 & 0x3f, t2 >> 6 & 0x3f, t2 & 0x3f,
          t3 >> 18 & 0x3f, t3 >> 12 & 0x3f, t3 >> 6 & 0x3f ]
    # Convert to characters.
    for i in xrange(len(r)):
        r[i] = _cov_2char[r[i]]
    return salt[:2] + string.join(r, '')

def _test():
    """Run doctest on fcrypt module."""
    import doctest, fcrypt
    return doctest.testmod(fcrypt)

if __name__ == '__main__':
    _test()
