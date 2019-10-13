#!/usr/bin/python3

from hexdump import hexdump

def hexdump_indent(data, lvl):
    """ Hexdump wrapper with indentation """
    indent = '\t' * lvl
    for line in hexdump(data, result='generator'):
        print("{}{}".format(indent, line))


