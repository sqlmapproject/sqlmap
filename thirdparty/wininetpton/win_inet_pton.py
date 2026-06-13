# This software released into the public domain. Anyone is free to copy,
# modify, publish, use, compile, sell, or distribute this software,
# either in source code form or as a compiled binary, for any purpose,
# commercial or non-commercial, and by any means.

import socket
import os
import sys


def inject_into_socket():
    import ctypes

    class in_addr(ctypes.Structure):
        _fields_ = [("S_addr", ctypes.c_ubyte * 4)]

    class in6_addr(ctypes.Structure):
        _fields_ = [("Byte", ctypes.c_ubyte * 16)]

    if hasattr(ctypes, "windll"):
        # InetNtopW(
        #   INT         family,
        #   const VOID  *pAddr,
        #   PWSTR       pStringBuf,
        #   size_t      StringBufSize
        # ) -> PCWSTR
        InetNtopW = ctypes.windll.ws2_32.InetNtopW

        # InetPtonW(
        #   INT         family,
        #   PCWSTR      pszAddrString,
        #   PVOID       pAddrBuf
        # ) -> INT
        InetPtonW = ctypes.windll.ws2_32.InetPtonW

        # WSAGetLastError() -> INT
        WSAGetLastError = ctypes.windll.ws2_32.WSAGetLastError
    else:

        def not_windows():
            raise SystemError("Invalid platform. ctypes.windll must be available.")

        InetNtopW = not_windows
        InetPtonW = not_windows
        WSAGetLastError = not_windows

    def inet_pton(address_family, ip_string):
        if sys.version_info[0] > 2 and isinstance(ip_string, bytes):
            raise TypeError("inet_pton() argument 2 must be str, not bytes")

        if address_family == socket.AF_INET:
            family = 2
            addr = in_addr()
        elif address_family == socket.AF_INET6:
            family = 23
            addr = in6_addr()
        else:
            raise OSError("unknown address family")

        ip_string = ctypes.c_wchar_p(ip_string)
        ret = InetPtonW(ctypes.c_int(family), ip_string, ctypes.byref(addr))

        if ret == 1:
            if address_family == socket.AF_INET:
                return ctypes.string_at(addr.S_addr, 4)
            else:
                return ctypes.string_at(addr.Byte, 16)
        elif ret == 0:
            raise socket.error("illegal IP address string passed to inet_pton")
        else:
            err = WSAGetLastError()
            if err == 10047:
                e = socket.error("unknown address family")
            elif err == 10014:
                e = OSError("bad address")
            else:
                e = OSError("unknown error from inet_ntop")
            e.errno = err
            raise e

    def inet_ntop(address_family, packed_ip):
        if address_family == socket.AF_INET:
            addr = in_addr()
            if len(packed_ip) != ctypes.sizeof(addr.S_addr):
                raise ValueError("packed IP wrong length for inet_ntop")

            ctypes.memmove(addr.S_addr, packed_ip, 4)
            buffer_len = 16
            family = 2

        elif address_family == socket.AF_INET6:
            addr = in6_addr()
            if len(packed_ip) != ctypes.sizeof(addr.Byte):
                raise ValueError("packed IP wrong length for inet_ntop")

            ctypes.memmove(addr.Byte, packed_ip, 16)
            buffer_len = 46
            family = 23
        else:
            raise ValueError("unknown address family")

        buffer = ctypes.create_unicode_buffer(buffer_len)

        ret = InetNtopW(
            ctypes.c_int(family),
            ctypes.byref(addr),
            ctypes.byref(buffer),
            buffer_len,
        )
        if ret is None:
            err = WSAGetLastError()
            if err == 10047:
                e = ValueError("unknown address family")
            else:
                e = OSError("unknown error from inet_ntop")
            e.errno = err
            raise e

        return ctypes.wstring_at(buffer, buffer_len).rstrip("\x00")

    # Adding our two functions to the socket library
    socket.inet_pton = inet_pton
    socket.inet_ntop = inet_ntop


if os.name == "nt" and not hasattr(socket, "inet_pton"):
    inject_into_socket()
