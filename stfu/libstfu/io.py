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
        self.sha = SHAInterface(parent)

    def update(self):
        """ Update various aspects of I/O or chipset state """
        self.timer += self.starlet.last_block_size * 0x10
        self.starlet.write32(0x0d800010, self.timer)
        self.nand.update()
        self.aes.update()
        self.sha.update()
        self.ahb.update()
        self.gpio.update()

# -----------------------------------------------------------------------------
class DummyInterface(object):
    """ Necessary part of this stupid solution for doing MMIO """
    def __init__(self): return
    def on_access(self, access, address, size, value): return

# -----------------------------------------------------------------------------

import hashlib

class SHAInterface(object):
    """ You *may* have to do wack FFI shit to call into some other SHA
    implementation, considering that this has not worked in the past for me
    """
    def __init__(self, parent):
        self.starlet = parent
        self.dma_src = 0
        self.req_done = False
        self.hbuf = bytearray(b'\x00'*0x14)

    def update(self):
        if (self.req_done == True):
            self.starlet.write32(0x0d030000, 
                self.starlet.read32(0x0d030000) & 0x7fffffff)
            self.req_done = False
        return

    def on_access(self, access, addr, size, value):
        if (access == UC_MEM_WRITE):
            if (addr == 0x0d030000):
                print("[*] SHA command write {:08x}".format(value))
                if ((value & 0x80000000) != 0):
                    num_bytes = ((value & 0xfff) + 1) * 0x40
                    print("[*] SHA started hashing {:08x} bytes at {:08x}".format(\
                            num_bytes, self.dma_src))
                    src_data = self.starlet.dma_read(self.dma_src, num_bytes)

                    print("[*] SHA current digest is {}".format(\
                            hexlify(self.hbuf).decode('utf-8')))

                    h = hashlib.sha1(self.hbuf)
                    h.update(src_data)
                    self.hbuf = h.digest()

                    print("[*] SHA new digest is {}".format(\
                            hexlify(self.hbuf).decode('utf-8')))

                    self.starlet.write32(0x0d030008, 
                            unpack(">L",self.hbuf[0x00:0x04])[0])
                    self.starlet.write32(0x0d03000c, 
                            unpack(">L",self.hbuf[0x04:0x08])[0])
                    self.starlet.write32(0x0d030010, 
                            unpack(">L",self.hbuf[0x08:0x0c])[0])
                    self.starlet.write32(0x0d030014, 
                            unpack(">L",self.hbuf[0x0c:0x10])[0])
                    self.starlet.write32(0x0d030018, 
                            unpack(">L",self.hbuf[0x10:0x14])[0])
                    self.req_done = True

            elif (addr == 0x0d030004):
                print("[*] SHA set source address to {:08x}".format(value))
                self.dma_src = value

            elif (addr == 0x0d030008): self.hbuf[0x00:0x04] = pack(">L", value)
            elif (addr == 0x0d03000c): self.hbuf[0x04:0x08] = pack(">L", value)
            elif (addr == 0x0d030010): self.hbuf[0x08:0x0c] = pack(">L", value)
            elif (addr == 0x0d030014): self.hbuf[0x0c:0x10] = pack(">L", value)
            elif (addr == 0x0d030018): self.hbuf[0x10:0x14] = pack(">L", value)

# -----------------------------------------------------------------------------

from Crypto.Cipher import AES

class AESInterface(object):
    FIFO_TIMEOUT = 10000

    def __init__(self, parent):
        self.starlet = parent

        self.dma_src = 0
        self.dma_dst = 0

        self.key_fifo = bytearray()
        self.key_bd = 0

        self.tmp_iv = bytearray(b'\x00'*0x10)
        self.iv_fifo = bytearray()
        self.iv_bd = 0

        self.req_done = False

    def update(self):
        if (self.req_done == True):
            self.req_done = False
            self.starlet.write32(0x0d020000, 
                self.starlet.read32(0x0d020000) & 0x7fffffff)

    def on_access(self, access, address, size, value):
        if (access == UC_MEM_WRITE):

            if (address == 0x0d020000):
                print("[*] AES command write {:08x}".format(value))

                # Instantaneously perform a command.
                # You might want to just enqueue it and run it with update(), 
                # which is probably a more accurate way of emulating it
                if ((value & 0x80000000) != 0):
                    iv_reset = True if ((value & 0x1000) != 0) else None
                    num_bytes = ((value & 0xfff) + 1) * 0x10
                    print("[*] AES DMA started, size={:08x}".format(num_bytes))

                    src_data = self.starlet.dma_read(self.dma_src, num_bytes)

                    # If this bit is cleared, we just do DMA without any AES
                    if ((value & 0x10000000) != 0):

                        if (iv_reset): _iv = self.tmp_iv
                        else: _iv = self.iv_fifo
                        cipher = AES.new(self.key_fifo, AES.MODE_CBC, iv=_iv)

                        # Decrypt data when this is set, encrypt when clear
                        if ((value & 0x08000000) != 0):
                            wdata = cipher.decrypt(src_data)
                        else:
                            wdata = cipher.encrypt(src_data)
                        self.starlet.dma_write(self.dma_dst, wdata)
                        print("[*] AES DMA wrote {:08x} to {:08x}".format(\
                            num_bytes, self.dma_dst))
                        hexdump_indent(wdata[0:0x100], 1)
                    else:
                        self.starlet.dma_write(self.dma_dst, src_data)
                        print("[*] AES DMA wrote {:08x} to {:08x}".format(\
                            num_bytes, self.dma_dst))
                        hexdump_indent(src_data[0:0x100], 1)

                    self.tmp_iv = self.starlet.dma_read(\
                            self.dma_src + num_bytes - 0x10, 0x10)
                    self.dma_src += num_bytes
                    self.dma_dst += num_bytes
                    self.req_done = True




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

