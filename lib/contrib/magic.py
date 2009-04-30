#!/usr/bin/env python

"""
$Id$

Adam Hupp <adam@hupp.org>

Reference: http://hupp.org/adam/hg/python-magic

License: PSF (http://www.python.org/psf/license/)
"""



import os.path
import ctypes
import ctypes.util

from ctypes import c_char_p, c_int, c_size_t, c_void_p

class MagicException(Exception): pass

class Magic:
    """
    Magic is a wrapper around the libmagic C library.  
    
    """

    def __init__(self, mime=False, magic_file=None):
        """
        Create a new libmagic wrapper.

        mime - if True, mimetypes are returned instead of textual descriptions
        magic_file - use a mime database other than the system default
        
        """
        flags = MAGIC_NONE
        if mime:
            flags |= MAGIC_MIME
            
        self.cookie = magic_open(flags)

        magic_load(self.cookie, magic_file)


    def from_buffer(self, buf):
        """
        Identify the contents of `buf`
        """
        return magic_buffer(self.cookie, buf)

    def from_file(self, filename):
        """
        Identify the contents of file `filename`
        raises IOError if the file does not exist
        """

        if not os.path.exists(filename):
            raise IOError("File does not exist: " + filename)
        
        return magic_file(self.cookie, filename)

    def __del__(self):
        try:
            magic_close(self.cookie)
        except Exception, _:
            pass


_magic_mime = None
_magic = None

def _get_magic_mime():
    global _magic_mime
    if not _magic_mime:
        _magic_mime = Magic(mime=True)
    return _magic_mime

def _get_magic():
    global _magic
    if not _magic:
        _magic = Magic()
    return _magic

def _get_magic_type(mime):
    if mime:
        return _get_magic_mime()
    else:
        return _get_magic()

def from_file(filename, mime=False):
    m = _get_magic_type(mime)
    return m.from_file(filename)

def from_buffer(buffer, mime=False):
    m = _get_magic_type(mime)
    return m.from_buffer(buffer)



try:
    libmagic = ctypes.CDLL(ctypes.util.find_library('magic'))

    magic_t = ctypes.c_void_p

    def errorcheck(result, func, args):
        err = magic_error(args[0])
        if err is not None:
            raise MagicException(err)
        else:
            return result

    magic_open = libmagic.magic_open
    magic_open.restype = magic_t
    magic_open.argtypes = [c_int]

    magic_close = libmagic.magic_close
    magic_close.restype = None
    magic_close.argtypes = [magic_t]
    magic_close.errcheck = errorcheck

    magic_error = libmagic.magic_error
    magic_error.restype = c_char_p
    magic_error.argtypes = [magic_t]

    magic_errno = libmagic.magic_errno
    magic_errno.restype = c_int
    magic_errno.argtypes = [magic_t]

    magic_file = libmagic.magic_file
    magic_file.restype = c_char_p
    magic_file.argtypes = [magic_t, c_char_p]
    magic_file.errcheck = errorcheck


    _magic_buffer = libmagic.magic_buffer
    _magic_buffer.restype = c_char_p
    _magic_buffer.argtypes = [magic_t, c_void_p, c_size_t]
    _magic_buffer.errcheck = errorcheck


    def magic_buffer(cookie, buf):
        return _magic_buffer(cookie, buf, len(buf))


    magic_load = libmagic.magic_load
    magic_load.restype = c_int
    magic_load.argtypes = [magic_t, c_char_p]
    magic_load.errcheck = errorcheck

    magic_setflags = libmagic.magic_setflags
    magic_setflags.restype = c_int
    magic_setflags.argtypes = [magic_t, c_int]

    magic_check = libmagic.magic_check
    magic_check.restype = c_int
    magic_check.argtypes = [magic_t, c_char_p]

    magic_compile = libmagic.magic_compile
    magic_compile.restype = c_int
    magic_compile.argtypes = [magic_t, c_char_p]
except:
    pass


MAGIC_NONE = 0x000000 # No flags

MAGIC_DEBUG = 0x000001 # Turn on debugging

MAGIC_SYMLINK = 0x000002 # Follow symlinks

MAGIC_COMPRESS = 0x000004 # Check inside compressed files

MAGIC_DEVICES = 0x000008 # Look at the contents of devices

MAGIC_MIME = 0x000010 # Return a mime string

MAGIC_CONTINUE = 0x000020 # Return all matches

MAGIC_CHECK = 0x000040 # Print warnings to stderr

MAGIC_PRESERVE_ATIME = 0x000080 # Restore access time on exit

MAGIC_RAW = 0x000100 # Don't translate unprintable chars

MAGIC_ERROR = 0x000200 # Handle ENOENT etc as real errors

MAGIC_NO_CHECK_COMPRESS = 0x001000 # Don't check for compressed files

MAGIC_NO_CHECK_TAR = 0x002000 # Don't check for tar files

MAGIC_NO_CHECK_SOFT = 0x004000 # Don't check magic entries

MAGIC_NO_CHECK_APPTYPE = 0x008000 # Don't check application type

MAGIC_NO_CHECK_ELF = 0x010000 # Don't check for elf details

MAGIC_NO_CHECK_ASCII = 0x020000 # Don't check for ascii files

MAGIC_NO_CHECK_TROFF = 0x040000 # Don't check ascii/troff

MAGIC_NO_CHECK_FORTRAN = 0x080000 # Don't check ascii/fortran

MAGIC_NO_CHECK_TOKENS = 0x100000 # Don't check ascii/tokens
