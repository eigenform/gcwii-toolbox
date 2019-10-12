#!/usr/bin/python3

from struct import pack, unpack
from pywiire.util import *

BOOT2_MAGIC         = b'\x26\xf2\x9a\x40\x1e\xe6\x84\xcf'
SFFS_MAGIC          = b'SFFS'

# Globals for NAND geometry 
TOTAL_PAGE_SIZE     = 0x840
METADATA_SIZE       = 0x040
USERDATA_SIZE       = 0x800
BLOCK_SIZE          = 64


class Boot2Map(object):
    """ A boot2 blockmap. I don't actually know if we prefer ordering by
    the generation number, or just by the offset it lives at? FIXME
    """
    def __lt__(self, x):
        """ Enforce ordering by generation number? """
        return self.gen < x.gen

    def __init__(self, data):
        assert data[0x00:0x08] == BOOT2_MAGIC
        assert len(data) == 0x4c
        self.data = data
        self.magic, self.gen = unpack(">QL", data[0x00:0x0c])
        self.valid_blocks = []

        # Each valid block is marked with an 0x00 byte
        for block_num in range(0, 0x40):
            if (data[(0x0c + block_num):(0x0c + block_num + 1)] == b'\x00'):
                valid_blocks.append(block_num)

class FAT(object):
    """ Object representing an SFFS file allocation table """

    BLOCK_LAST          = 0xfffb
    BLOCK_RESERVED      = 0xfffc
    BLOCK_BAD           = 0xfffd
    BLOCK_FREE          = 0xfffe

    def __lt__(self, x):
        """ We want to order FAT objects by the generation number """
        return self.gen < x.gen

    def __init__(self, off, data):
        assert data[0x00:0x04] == SFFS_MAGIC
        assert len(data) == 0x1000c
        self.offset = off
        self.data = data
        self.magic = unpack(">L", data[0x00:0x04])[0]
        self.gen = unpack(">L", data[0x04:0x08])[0]

        # Generate a list of blocks in this FAT
        self.block = []
        cur = 0x0c
        for i in range(0, 0x8000):
            self.block.append(unpack(">H", data[cur:cur+0x2])[0])
            cur += 0x2
        assert len(self.block) == 0x8000

        # Generate list of various interesting blocks
        self.free_blocks = []
        for idx, block in enumerate(self.block):
            if (self.block[idx] == BLOCK_FREE): 
                self.free_blocks.append(idx)


class NAND(object):
    """ Object representing a NAND flash dump.
    Yes, we are probably condemned to having to keep the whole thing in RAM
    because it's slightly easier. Not ideal, but luckily it's only like 512MB.
    """

    def __init__(self, data):
        self.data = data

        # Find all boot2 block maps
        self.boot2_map = []
        for off in find_all(BOOT2_MAGIC, data):
            self.boot2_map.append(Boot2Map(data[off:off+0x4c]))
        self.boot2_map.sort()

        




