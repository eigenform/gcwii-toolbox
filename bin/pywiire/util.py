#!/usr/bin/python3

from hexdump import hexdump
from struct import pack, unpack

def find_all(pattern, data):
    """ Return a list of all match offsets in the target bytearray """
    cur = 0
    res = []
    while (cur < len(data)):
        cur = data.find(pattern, cur)
        if (cur == -1): break
        res.append(cur)
        cur += len(pattern)
    return res

def dump(data, lvl):
    """ Hexdump wrapper with indentation """
    indent = '\t' * lvl
    for line in hexdump(data, result='generator'):
        print("{}{}".format(indent, line))

