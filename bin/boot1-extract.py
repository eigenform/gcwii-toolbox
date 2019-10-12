#!/usr/bin/python3

from sys import argv
from pywiire.keys import *
from pywiire.nand import *

from Crypto.Cipher import AES
from Crypto.Hash import SHA1

if (len(argv) < 3):
    print("usage: {} <nand.bin> <output file>".format(argv[0]))
    exit()

# Setup this AES object to decrypt all of the boot1 pages
boot1_key = read_key("boot1")
boot1_iv = b'\x00' * 0x10
cipher = AES.new(boot1_key, AES.MODE_CBC, boot1_iv)
digest = SHA1.new()

# Just read the first 0x40 pages (everything else isn't relevant to boot1)
with open(argv[1], "rb") as f:
    data = f.read(TOTAL_PAGE_SIZE * 0x40)

# The boot1 hash stored in OTP is taken over the first 0x2f pages.
# FIXME: The data here will be correct, but the computed SHA-1 digest will 
# be WRONG for some reason - why does it work in C but not in Python?
ddata = bytearray()
for pnum in range(0, 0x2f):
    dpage = bytearray()
    page = data[(TOTAL_PAGE_SIZE * pnum):((TOTAL_PAGE_SIZE * pnum) + 0x800)]
    dpage = cipher.decrypt(page)
    digest.update(dpage)
    ddata += dpage

print("[!] FIXME: this digest will NOT match the OTP boot1 digest!")
print("[*] SHA-1 digest: {}".format(digest.hexdigest()))

with open(argv[2], "wb") as f:
    f.write(ddata)
    print("[*] Wrote {:08x} bytes to {}".format(len(ddata), argv[2]))
