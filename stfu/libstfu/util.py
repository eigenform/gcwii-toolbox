#!/usr/bin/python3

from hexdump import hexdump
from struct import pack, unpack
from hashlib import sha256
import signal

""" 
Wrappers and helper functions for various logging tasks
"""

INFO = 1
WARN = 2
def log(fmt, *args): print("[*] " + fmt.format(*args))
def warn(fmt, *args): print("[!] " + fmt.format(*args))

def hexdump_idt(data, idtlvl):
    for l in hexdump(data, result='generator'): 
        print("{}{}".format('\t' * idtlvl, l))

""" 
Terse wrappers for common struct.{pack,unpack} use-cases
"""

def up16(data, num=1): return __unpack(data, 16, num)
def up32(data, num=1): return __unpack(data, 32, num)
def up64(data, num=1): return __unpack(data, 64, num)
def __unpack(data, width, num):
    assert num != 0
    if (width == 8): t = "b"
    elif (width == 16): t = "H"
    elif (width == 32): t = "L"
    elif (width == 64): t = "Q"
    fmt = ">" + t * num
    if (num == 1): return unpack(fmt, data)[0]
    else: return unpack(fmt, data)


"""
Signal handling; mostly for terminating user applications
"""

def __gen_sigint_handler(starlet_inst):
    """ Generate a SIGINT handler that halts a Starlet() instance """

    # FIXME: assert type(starlet_inst) == Starlet
    def __stfu_handle_sigint(sig, frame):
        warn("Caught SIGINT, halting now!")
        starlet_inst.why = {"type": "sigint"}
        starlet_inst.mu.emu_stop()
    return __stfu_handle_sigint

def stfu_register_sigint_handler(starlet_inst):
    """ Register a SIGINT handler """
    signal.signal(signal.SIGINT, __gen_sigint_handler(starlet_inst))


