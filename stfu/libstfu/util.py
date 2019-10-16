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


"""
Helper functions for dealing with ECC
"""

def parity(x):
    y = 0
    while (x != 0):
        y ^= (x & 1)
        x >>= 1
    return y

def calc_ecc(data):
    ecc = [ 0, 0, 0, 0 ]

    a = []
    for i in range(0, 12): a.append([0, 0])

    for i in range(0, 512):
        for j in range(0, 9):
            a[3+j][(i>>j)&1] ^= data[i]

    x = a[3][0] ^ a[3][1]
    a[0][0] = x & 0x55
    a[0][1] = x & 0xaa
    a[1][0] = x & 0x33
    a[1][1] = x & 0xcc
    a[2][0] = x & 0x0f
    a[2][1] = x & 0xf0

    for j in range(0, 12):
        a[j][0] = parity(a[j][0])
        a[j][1] = parity(a[j][1])

    a0 = 0
    a1 = 0
    for j in range(0, 12):
        a0 |= (a[j][0] << j) & 0xffffffff
        a1 |= (a[j][1] << j) & 0xffffffff

    ecc[0] = a0 & 0xff;
    ecc[1] = (a0 >> 8) & 0xff
    ecc[2] = a1 & 0xff
    ecc[3] = (a1 >> 8) & 0xff

    return (ecc[0] << 24 | ecc[1] << 16 | ecc[2] << 8 | ecc[3])

