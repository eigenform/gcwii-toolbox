#!/usr/bin/python3
""" libstfu/io.py
Built on the backs of giants (thanks team twiizers) :^)
"""

from unicorn.arm_const import *
from unicorn.unicorn_const import *

from libstfu.hollywood_defs import *
from libstfu.util import *

from binascii import hexlify, unhexlify
from struct import pack, unpack

class StarletIO(object):
    """ Top-level container for managing Hollywood and I/O device state """
    def __init__(self, parent):

        self.hcnt = 0x2000      # Period of I/O updates in number of instrs
        self.timer = 0          # Hollywood timer state

        self.starlet = parent
        self.dummy = DummyInterface(parent)

        self.nand = NANDInterface(parent)
        self.ahb = AHBInterface(parent)
        self.gpio = GPIOInterface(parent)
        self.aes = AESInterface(parent, self)
        self.sha = SHAInterface(parent)
        self.otp = OTPInterface(parent)
        self.ipc = IPCInterface(parent)
        self.hlwd = HollywoodInterface(parent)
        self.intc = InterruptInterface(parent)
        self.ehci = EHCInterface(parent)

        self.ohci0 = OHCInterface(parent)
        self.ohci1 = OHCInterface(parent)

    def update(self):
        """ Update various aspects of I/O or chipset state """

        # The period of the timer is 526.7ns, about twice a us
        self.timer += self.hcnt * 2
        if (self.timer >= 0xffffffff):
            self.timer = 0
        self.starlet.write32(HW_TIMER, self.timer)

        self.nand.update()
        self.aes.update()
        self.sha.update()
        self.ahb.update()
        self.gpio.update()

# -----------------------------------------------------------------------------
class DummyInterface(object):
    """ Necessary part of this stupid solution for doing MMIO """
    def __init__(self, parent): 
        self.starlet = parent
    def on_access(self, access, addr, size, value): 
        return

# -----------------------------------------------------------------------------
class OHCInterface(object):
    """ EHCI container """
    def __init__(self, parent): 
        self.starlet = parent

    def on_access(self, access, addr, size, value): 
        return



# -----------------------------------------------------------------------------
class EHCInterface(object):
    """ EHCI container """
    def __init__(self, parent): 
        self.starlet = parent

    def on_access(self, access, addr, size, value): 
        return


# -----------------------------------------------------------------------------
class InterruptInterface(object):
    """ Container for 'interrupt controller' interface[s] """
    def __init__(self, parent): 
        self.starlet = parent
    def on_access(self, access, addr, size, value): 
        return

# -----------------------------------------------------------------------------
class HollywoodInterface(object):
    """ Bin for unsorted/unknown/miscellaneous Hollywood registers """
    def __init__(self, parent): 
        self.starlet = parent
        self.sram_mirror = False    # This object's view of the mirror state
        self.brom_mapped = True     # This object's view of the BROM state

    def update(self): return
    def on_access(self, access, addr, size, value): 
        if (access == UC_MEM_WRITE):
            if (addr == HW_SPARE0): self.starlet.io.ahb.spare0_flags = value
            if (addr == HW_MEMIRR):
                self.sram_mirror = True if ((value & 0x20) != 0) else False
                self.starlet.sram_mirror_next  = self.sram_mirror
            if (addr == HW_BOOT0):
                self.brom_mapped = False if ((value & 0x1000) != 0) else True
                self.starlet.brom_mapped_next  = self.brom_mapped


# -----------------------------------------------------------------------------
class IPCInterface(object):
    """ Container for the IPC interface (this might get complicated later) """
    def __init__(self, parent): 
        self.starlet = parent
    def on_access(self, access, addr, size, value): 
        warn("IPC interface unimplemented")
        self.starlet.halt("unimpl")

# -----------------------------------------------------------------------------

class AHBInterface(object):
    """ Container for the memory controller """
    def __init__(self, parent):
        self.starlet = parent
        self.flush_req = None
        self.spare0_flags = None

    def update(self):
        if (self.spare0_flags != None):
            boot0 = self.starlet.read32(HW_BOOT0)
            if ((self.spare0_flags & 0x10000) != 0x10000): boot0 |= 9
            else: boot0 &= 0xfffffff6
            self.starlet.write32(HW_BOOT0, boot0)
            self.spare0_flags = None

        # ACK a pending flush request
        if (self.flush_req != None):
            self.starlet.write16(MEM_FLUSHACK, self.flush_req)
            #log("AHB ack flush ({:04x})", self.flush_req)
            self.flush_req = None

    def on_access(self, access, addr, size, value): 
        acc = "write" if access == UC_MEM_WRITE else "read"
        #log("AHB {} on {:08x}", acc, addr)
        if (access == UC_MEM_WRITE):
            if (addr == MEM_FLUSHREQ): 
                self.flush_req = value


# -----------------------------------------------------------------------------
class OTPInterface(object):
    """ Container for interface to one-time programmable memory """
    def __init__(self, parent):
        self.starlet = parent
        self.data = bytearray()

    def update(self):
        return

    def on_access(self, access, addr, size, value):
        if (access == UC_MEM_WRITE):
            if (addr == EFUSE_ADDR):
                if ((value & 0x80000000) != 0):
                    addr = value & 0x1f
                    otp_word = up32(self.data[addr*4:(addr*4)+4])
                    self.starlet.write32(EFUSE_DATA, otp_word)
                    #log("OTP read: addr={:02x}, res={:08x}", addr, otp_word)
                    self.starlet.write32(EFUSE_ADDR, 0) # FIXME: ????


# -----------------------------------------------------------------------------

class GPIOInterface(object):
    """ Container for interface to Broadway/Starlet GPIOs """
    def __init__(self, parent):
        self.starlet = parent
        self.arm_out = 0

    def update(self):
        #out = self.starlet.read32(GPIO_OUT)
        #if (self.arm_out != out):
        #    log("ARMGPIO output set to {:08x}", out)
        #    self.arm_out = out
        return

    def on_access(self, access, addr, size, value): 
        if (access == UC_MEM_WRITE):
            #if (addr == GPIO_OUT): log("ARMGPIO output set to {:08x}", value)
            pass
        return


# -----------------------------------------------------------------------------

import hashlib

from libstfu.ffi_sha import *
import ctypes

class SHAInterface(object):
    """ Container for the SHA-1 engine """
    def __init__(self, parent):
        self.starlet = parent
        self.dma_src = 0
        self.req_done = False

    def update(self):
        if (self.req_done == True):

            # Flush digest to SHA1 interface registers
            self.starlet.write32(SHA_H0, ffi_sha1_get(0))
            self.starlet.write32(SHA_H1, ffi_sha1_get(1))
            self.starlet.write32(SHA_H2, ffi_sha1_get(2))
            self.starlet.write32(SHA_H3, ffi_sha1_get(3))
            self.starlet.write32(SHA_H4, ffi_sha1_get(4))

            #log("SHA digest updated to:\t {:08x}{:08x}{:08x}{:08x}{:08x}",
            #        ffi_sha1_get(0), ffi_sha1_get(1), ffi_sha1_get(2),
            #        ffi_sha1_get(3), ffi_sha1_get(4))

            # Indicate that we've completed the request
            self.starlet.write32(SHA_CTRL,
                self.starlet.read32(SHA_CTRL) & 0x7fffffff)

            # Update the state of the source buffer
            self.starlet.write32(SHA_SRC, self.dma_src)

            self.req_done = False
        return

    def on_access(self, access, addr, size, value):
        if (access == UC_MEM_WRITE):
            if (addr == SHA_CTRL):
                if ((value & 0x80000000) != 0):
                    self.handle_command(value)
                    self.req_done = True
            elif (addr == SHA_SRC): self.dma_src = value
            elif (addr == SHA_H0): ffi_sha1_set(0, value)
            elif (addr == SHA_H1): ffi_sha1_set(1, value)
            elif (addr == SHA_H2): ffi_sha1_set(2, value)
            elif (addr == SHA_H3): ffi_sha1_set(3, value)
            elif (addr == SHA_H4): ffi_sha1_set(4, value)

    def handle_command(self, val):
        num_bytes = ((val & 0xfff) + 1) * 0x40
        #log("SHA dma src={:08x}, len={:08x}", self.dma_src, num_bytes)
        src_data = self.starlet.dma_read(self.dma_src, num_bytes)
        #hexdump_idt(src_data, 1)
        buf = ctypes.c_ubyte * num_bytes
        ptr = buf.from_buffer(src_data)
        ffi_sha1_input(ptr, num_bytes)
        self.dma_src += num_bytes

# -----------------------------------------------------------------------------

from Crypto.Cipher import AES

AES_FIFO_TIMEOUT = 1000
class AESInterface(object):
    """ Container for the AES engine """

    def __init__(self, parent, io):
        self.starlet = parent
        self.io = io

        self.dma_src = 0
        self.dma_dst = 0
        self.req_done = False

        self.tmp_iv = bytearray(b'\x00'*0x10)

        self.key_fifo = bytearray(b'\x00'*0x10)
        self.iv_fifo = bytearray(b'\x00'*0x10)

        self.key_fifo_open = False
        self.iv_fifo_open = False

        self.key_fifo_timer = 0
        self.iv_fifo_timer = 0
        self.key_fifo_idx = 0
        self.iv_fifo_idx = 0

    def update(self):
        # Handle the key FIFO window
        if (self.key_fifo_open == True):
            ktimer_diff = self.io.timer - self.key_fifo_timer
            if (ktimer_diff >= AES_FIFO_TIMEOUT):
                self.key_fifo_open = False
                self.key_fifo_timer = 0

        # Handle the IV FIFO window
        if (self.iv_fifo_open == True):
            itimer_diff = self.io.timer - self.iv_fifo_timer
            if (itimer_diff >= AES_FIFO_TIMEOUT):
                self.iv_fifo_open = False
                self.iv_fifo_timer = 0

        # Update MMIO register state
        if (self.req_done == True):
            self.req_done = False
            self.starlet.write32(AES_CTRL,
                self.starlet.read32(AES_CTRL) & 0x7fffffff)
            self.starlet.write32(AES_SRC, self.dma_src)
            self.starlet.write32(AES_DST, self.dma_dst)

    def on_access(self, access, addr, size, value):
        if (access == UC_MEM_WRITE):
            if (addr == AES_CTRL):
                if ((value & 0x80000000) != 0):
                    self.handle_command(value)
                    self.req_done = True
            elif (addr == AES_SRC): self.dma_src = value
            elif (addr == AES_DST): self.dma_dst = value
            elif (addr == AES_KEY):
                if (self.key_fifo_open == False):
                    self.key_fifo_open = True
                    self.key_fifo_idx = 0
                    self.key_fifo_timer = self.io.timer
                    self.key_fifo_update(value)
                else:
                    self.key_fifo_update(value)
            elif (addr == AES_IV):
                if (self.iv_fifo_open == False):
                    self.iv_fifo_open = True
                    self.iv_fifo_idx = 0
                    self.iv_fifo_timer = self.io.timer
                    self.iv_fifo_update(value)
                else:
                    self.iv_fifo_update(value)

            
    def handle_command(self, val):
        num_bytes = ((val & 0xfff) + 1) * 0x10

        # Read the source data from AES_SRC
        src_data = self.dma_read(self.dma_src, num_bytes)

        # If this bit is cleared, we just do DMA without any AES
        if ((val & 0x10000000) != 0):
            _iv = self.tmp_iv if ((val & 0x1000) != 0) else self.iv_fifo
            cipher = AES.new(self.key_fifo, AES.MODE_CBC, iv=_iv)
            if ((val & 0x08000000) != 0):
                wdata = cipher.decrypt(src_data)
            else:
                wdata = cipher.encrypt(src_data)
            self.dma_write(self.dma_dst, wdata)
        else:
            self.dma_write(self.dma_dst, src_data)

        # Update the chain IV and new AES_{SRC,DST} values
        cur = num_bytes - 0x10
        del self.tmp_iv
        self.tmp_iv = src_data[cur:cur+0x10]
        self.dma_src += num_bytes
        self.dma_dst += num_bytes

    def dma_read(self, addr, size):
        #log("AES DMA read: addr={:08x}, len={:08x}", addr, size)
        data = self.starlet.dma_read(self.dma_src, size)
        #hexdump_idt(data, 1)
        return data

    def dma_write(self, addr, data):
        #log("AES DMA write: addr={:08x}, len={:08x}", addr, len(data))
        #hexdump_idt(data, 1)
        self.starlet.dma_write(addr, data)

    def key_fifo_update(self, val):
        entry = pack(">L", val)
        cur = self.key_fifo_idx * 4
        self.key_fifo[cur:cur+4] = entry
        self.key_fifo_idx += 1
        fifo_bytes = hexlify(self.key_fifo).decode('utf-8')

    def iv_fifo_update(self, val):
        entry = pack(">L", val)
        cur = self.iv_fifo_idx * 4
        self.iv_fifo[cur:cur+4] = entry
        self.iv_fifo_idx += 1
        fifo_bytes = hexlify(self.iv_fifo).decode('utf-8')




# -----------------------------------------------------------------------------

NAND_FLAG_WAIT          = 0x08
NAND_FLAG_WRITE         = 0x04
NAND_FLAG_READ          = 0x02
NAND_FLAG_ECC           = 0x01
NAND_CMD_RESET          = 0xff
NAND_CMD_READ0b         = 0x30
NAND_PAGE_LEN           = 0x840

class NANDInterface(object):
    """ Container for a NAND device """
    def __init__(self, parent):
        self.starlet = parent
        self.data = bytearray()
        self.req_done = False

        self.config = 0
        self.addr0 = 0
        self.addr1 = 0
        self.dma_data_addr = 0
        self.dma_ecc_addr = 0

    def update(self):
        if (self.req_done == True):
            ctrl = self.starlet.read32(NAND_CTRL)
            self.starlet.write32(NAND_CTRL, ctrl & 0x7fffffff)
            self.req_done = False
        return

    def on_access(self, access, addr, size, value):
        if (access == UC_MEM_WRITE):
            if (addr == NAND_CTRL):
                if ((value & 0x80000000) != 0):
                    self.handle_command(value)
                    self.req_done = True
            elif (addr == NAND_CFG): self.config = value
            elif (addr == NAND_ADDR0): self.addr0 = value
            elif (addr == NAND_ADDR1): self.addr1 = value
            elif (addr == NAND_DATABUF): self.dma_data_addr = value
            elif (addr == NAND_ECCBUF): self.dma_ecc_addr = value

    def handle_command(self, ctrl):
        """ Handle/request/complete a NAND interface command """
        mask = (ctrl & 0x1f000000) >> 24
        cmd = (ctrl & 0x00ff0000) >> 16
        flags = (ctrl & 0x0000f000) >> 12
        datasize = (ctrl & 0x00000fff)

        if ((flags & NAND_FLAG_WRITE) != 0):
            warn("NAND write flags unimplemented?")
            self.starlet.halt("unimpl")

        if (cmd == 0x00): pass
        elif (cmd == NAND_CMD_RESET): pass
        elif(cmd == NAND_CMD_READ0b):
            nand_data = self.nand_read(datasize)
            if (datasize <= 0x800):
                self.dma_write(self.dma_data_addr, nand_data)
            elif (datasize == 0x840):
                blk_data = nand_data[0x000:0x800]
                ecc_data = nand_data[0x800:0x840]
                #log("NAND read page addr1={:08x} dest={:08x}", 
                #    self.addr1, self.dma_data_addr)
                self.dma_write(self.dma_data_addr, blk_data)
                self.dma_write(self.dma_ecc_addr, ecc_data)
                if ((flags & NAND_FLAG_ECC) != 0):
                    for i in range(0, 4):
                        data = nand_data[i * 512:(i * 512)+512]
                        daddr = (self.dma_ecc_addr ^ 0x40) + i * 4
                        ecc = calc_ecc(data)
                        self.starlet.write32(daddr, ecc)
                        #log("wrote ecc {:08x} at {:08x}", ecc, daddr)
            else:
                log("NAND unimpl datasize")
                self.starlet.halt("unimpl")
        else:
            log("NAND: Unhandled cmd {:02x} ({:08x})", cmd, ctrl)
            self.starlet.halt("unimpl")

    def dma_write(self, addr, data):
        self.starlet.dma_write(addr, data)
        #log("NAND DMA write: addr={:08x}, len={:08x}", addr, len(data))
        #hexdump_idt(self.starlet.dma_read(addr, 0x100), 1)

    def nand_read(self, size):
        """ Return bytes from the underlying NAND device """
        off = self.addr1 * NAND_PAGE_LEN
        return self.data[off:off + size]

    def fix_all_ecc(self, plist=None):
        if (plist == None):
            plist = []
            total_pages = (len(self.data) // 0x840) - 2
            for pn in range(total_pages): plist.append(pn)

        for pn in plist:
            p_off = pn * 0x840
            for i in range(0, 4):
                data_off = p_off + (0x200 * i)
                ecc = calc_ecc(self.data[data_off:data_off+0x200])
                ecc_off = p_off + 0x830 + (i * 4)
                #x = unpack(">L", self.data[ecc_off:ecc_off+4])
                self.data[ecc_off:ecc_off+4] = pack(">L", ecc)

