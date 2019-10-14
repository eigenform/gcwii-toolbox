#!/usr/bin/python3

from hexdump import hexdump

INFO    = 1
WARN    = 2

def log(fmt, *args):
    print("[*] " + fmt.format(*args))
def warn(fmt, *args):
    print("[!] " + fmt.format(*args))

def hexdump_indent(data, lvl):
    """ Hexdump wrapper with indentation """
    indent = '\t' * lvl
    for line in hexdump(data, result='generator'):
        print("{}{}".format(indent, line))


