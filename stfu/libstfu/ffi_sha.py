#!/usr/bin/python3
""" ffi_sha.py

This is nasty but, for some reason, I couldn't get SHA1 digests to work out 
correctly in hashlib and I'm too lazy/stupid to figure it out. Perhaps there's 
some weird endianness thing going on there, or something about Python [not] 
making copies of data, I'm not sure.
"""

from ctypes import *

# We kind of assume here that you're always invoking `stfu` from the project
# root directory; this will probably be the only possible case.

try:
    __mysha = cdll.LoadLibrary("libstfu/mysha.so")
except OSError as e:
    print("[!] {}".format(e))
    exit()

ffi_sha1_set                = __mysha['ffi_sha1_set']
ffi_sha1_set.argtypes       = [ c_uint, c_uint ]
ffi_sha1_set.restype        = None

ffi_sha1_get                = __mysha['ffi_sha1_get']
ffi_sha1_get.argtypes       = [ c_uint ]
ffi_sha1_get.restype        = c_uint

ffi_sha1_input              = __mysha['ffi_sha1_input']
ffi_sha1_input.argtypes     = [ POINTER(c_char), c_uint ]
#ffi_sha1_input.argtypes     = [ c_void_p, c_size_t ]
ffi_sha1_input.restype      = None

