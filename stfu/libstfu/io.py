#!/usr/bin/python3

from unicorn.arm_const import *
from unicorn.unicorn_const import *
from libstfu.util import *

from binascii import hexlify, unhexlify
from struct import pack, unpack

class StarletIO(object):
    """ Top-level container for managing I/O device state """
    def __init__(self, parent):
        self.timer = 0
        self.starlet = parent

        # This is just a dummy interface 
        self.dummy = DummyInterface()

        self.nand = NANDInterface(parent)
        self.ahb = AHBInterface(parent)
        self.gpio = GPIOInterface(parent)
        self.aes = AESInterface(parent)

    def update(self):
        """ Update various aspects of I/O or chipset state """
        self.timer += self.starlet.last_block_size * 0x10
        self.starlet.write32(0x0d800010, self.timer)
        self.nand.update()
        self.aes.update()
        self.ahb.update()
        self.gpio.update()

# -----------------------------------------------------------------------------
class DummyInterface(object):
    """ Necessary part of this stupid solution for doing MMIO """
    def __init__(self): return
    def on_access(self, access, address, size, value): return


# -----------------------------------------------------------------------------
# NOTE: As I'm writing this, I forsee a problem with using PyCrypto's SHA-1 

from Crypto.Cipher import AES

class AESInterface(object):
    FIFO_TIMEOUT = 10000

    def __init__(self, parent):
        self.starlet = parent

        self.dma_src = 0
        self.dma_dst = 0

        self.key_fifo = bytearray()
        self.key_bd = 0

        self.iv_fifo = bytearray()
        self.iv_bd = 0

    def update(self):
        return

    def on_access(self, access, address, size, value):
        if (access == UC_MEM_WRITE):

            if (address == 0x0d020004):
                print("[*] AES set DMA source to {:08x}".format(value))
                self.dma_src = value
            if (address == 0x0d020008):
                print("[*] AES set DMA dest to {:08x}".format(value))
                self.dma_dst = value

            # Emulate the AES key FIFO
            if (address == 0x0d02000c):
                if ((self.starlet.io.timer - self.key_bd) > self.FIFO_TIMEOUT):
                    self.key_fifo = bytearray()
                self.key_fifo += pack(">L", value)
                fifo_bytes = hexlify(self.key_fifo).decode('utf-8')
                print("[*] AES got {:08x} from key FIFO (key={})".format(value, 
                    fifo_bytes))

            # Emulate the AES iv FIFO
            if (address == 0x0d020010):
                if ((self.starlet.io.timer - self.iv_bd) > self.FIFO_TIMEOUT):
                    self.iv_fifo = bytearray()

                self.iv_fifo += pack(">L", value)
                fifo_bytes = hexlify(self.iv_fifo).decode('utf-8')
                print("[*] AES got {:08x} from iv FIFO (key={})".format(value, 
                    fifo_bytes))



# -----------------------------------------------------------------------------

class AHBInterface(object):
    def __init__(self, parent):
        self.starlet = parent
        self.flush_req = 0
        self.spare0_flags = 0

    def update(self):
        # Immediately ACK flush requests (i think this is how this works)
        req = self.starlet.read16(0x0d8b4228)
        if (req != 0):
            print("[*] AHB acked flush request {:04x}".format(req))
            self.starlet.write16(0x0d8b422a, req)

        spare0 = self.starlet.read32(0x0d800188)
        if (self.spare0_flags != spare0):
            self.spare0_flags = spare0
            boot0 = self.starlet.read32(0x0d80018c)
            if ((spare0 & 0x10000) != 0x10000): 
                boot0 |= 9
            else:
                boot0 &= 0xffffffff6
            self.starlet.write32(0x0d80018c, boot0)
            print("[*] PLAT: Spare 0 write {:08x}, set boot0 to {:08x}"\
                    .format(spare0, boot0))

# -----------------------------------------------------------------------------

class GPIOInterface(object):
    def __init__(self, parent):
        self.starlet = parent
        self.arm_out = 0

    def update(self):
        out = self.starlet.read32(0x0d8000e0)
        if (self.arm_out != out):
            print("[!] ARMGPIO output set to {:08x}".format(out))
            self.arm_out = out


# -----------------------------------------------------------------------------

NAND_FLAG_WAIT          = 0x08
NAND_FLAG_WRITE         = 0x04
NAND_FLAG_READ          = 0x02
NAND_FLAG_ECC           = 0x01
NAND_CMD_RESET          = 0xff
NAND_CMD_READ0b         = 0x30
NAND_PAGE_LEN           = 0x840

class NANDInterface(object):
    def __init__(self, parent):
        self.starlet = parent
        self.command = 0

        # Mock NAND data
        self.data = bytearray()
        #self.data += b'\xde\xad\xbe\xef' * 0x100000

    def update(self):
        ctrl = self.starlet.read32(0x0d010000)

        # Handle a command
        if (ctrl & 0x80000000):

            mask = (ctrl & 0x1f000000) >> 24
            cmd = (ctrl & 0x00ff0000) >> 16
            flags = (ctrl & 0x0000f000) >> 12
            datasize = (ctrl & 0x00000fff)

            print("[*] NAND mask={:02x} cmd={:02x} flags={:02x} size={:04x}"\
                    .format(mask, cmd, flags, datasize))

            # Just use command and size to infer what needs to happen?
            if (cmd == 0x00):
                self.clear_command(ctrl)

            elif (cmd == NAND_CMD_RESET):
                print("[*] NAND RESET")
                self.clear_command(ctrl)

            elif(cmd == NAND_CMD_READ0b):
                addr0           = self.starlet.read32(0x0d010008)
                addr1           = self.starlet.read32(0x0d01000c)
                dma_data_addr   = self.starlet.read32(0x0d010010)
                dma_ecc_addr    = self.starlet.read32(0x0d010014)

                print("[*] NAND READ data={:08x} ecc={:08x} a0={:08x} a1={:08x}"\
                    .format(dma_data_addr, dma_ecc_addr, addr0, addr1))

                if (datasize == 0x800):
                    nand_data = self.nand_read(addr0, addr1, datasize)
                    assert len(nand_data) == 0x800
                    self.starlet.dma_write(dma_data_addr, nand_data[0:0x800])
                    print("[!] NAND DMA write to {:08x}".format(dma_data_addr))
                    hexdump_indent(self.starlet.dma_read(dma_data_addr,0x100), 1)
                    self.clear_command(ctrl)

                elif (datasize == 0x840):
                    nand_bytes = self.nand_read(addr0, addr1, datasize)
                    blk_data = nand_bytes[0x000:0x800]
                    ecc_data = nand_bytes[0x800:0x840]
                    assert len(blk_data) == 0x800
                    assert len(ecc_data) == 0x040

                    self.starlet.dma_write(dma_data_addr, blk_data)
                    self.starlet.dma_write(dma_ecc_addr, ecc_data)

                    print("[!] NAND DMA write to {:08x}".format(dma_data_addr))
                    hexdump_indent(self.starlet.dma_read(dma_data_addr,0x100), 1)
                    print("[!] NAND DMA write to {:08x}".format(dma_ecc_addr))
                    hexdump_indent(self.starlet.dma_read(dma_ecc_addr,0x40), 1)
                    self.clear_command(ctrl)

                else:
                    print("[*] NAND unimpl datasize")
                    self.starlet.halt()
            else:
                print("[*] NAND: Unhandled cmd {:02x} ({:08x})".format(cmd, ctrl))
                self.starlet.halt()


    def clear_command(self, ctrl):
        """ Clear the NAND_CTRL busy bit """
        self.starlet.write32(0x0d010000, ctrl & 0x7fffffff)

    def nand_read(self, addr0, addr1, size):
        """ Return bytes from the underlying NAND device """
        off = addr1 * NAND_PAGE_LEN
        return self.data[off:off + size]

