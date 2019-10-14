#!/usr/bin/python3

from unicorn.arm_const import *
from unicorn.unicorn_const import *

from libstfu.hollywood_defs import *
from libstfu.util import *

from binascii import hexlify, unhexlify
from struct import pack, unpack

class StarletIO(object):
    """ Top-level container for managing Hollywood and I/O device state """
    def __init__(self, parent):
        self.timer = 0
        self.starlet = parent
        self.dummy = DummyInterface(parent)

        self.nand = NANDInterface(parent)
        self.ahb = AHBInterface(parent)
        self.gpio = GPIOInterface(parent)
        self.aes = AESInterface(parent)
        self.sha = SHAInterface(parent)
        self.otp = OTPInterface(parent)
        self.ipc = IPCInterface(parent)
        self.hlwd = HollywoodInterface(parent)
        self.intc = InterruptInterface(parent)

    def update(self):
        """ Update various aspects of I/O or chipset state """
        self.timer += self.starlet.last_block_size * 0x10
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

    def update(self):
        return

    def on_access(self, access, addr, size, value): 
        if (access == UC_MEM_WRITE):
            if (addr == HW_SPARE0): self.starlet.io.ahb.spare0_flags = value


# -----------------------------------------------------------------------------
class IPCInterface(object):
    """ Container for the IPC interface (this might get complicated later) """
    def __init__(self, parent): 
        self.starlet = parent
    def on_access(self, access, addr, size, value): 
        warn("IPC is unimplemented, dying")
        self.starlet.halt()
        return


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
                    log("OTP read: addr={:02x}, res={:08x}", addr, otp_word)
                    self.starlet.write32(EFUSE_ADDR, 0) # FIXME: ????


# -----------------------------------------------------------------------------

class GPIOInterface(object):
    """ Container for interface to Broadway/Starlet GPIOs """
    def __init__(self, parent):
        self.starlet = parent
        self.arm_out = 0

    def update(self):
        out = self.starlet.read32(GPIO_OUT)
        if (self.arm_out != out):
            log("ARMGPIO output set to {:08x}", out)
            self.arm_out = out

    def on_access(self, access, addr, size, value): 
        if (access == UC_MEM_WRITE):
            #if (addr == GPIO_OUT): log("ARMGPIO output set to {:08x}", out)
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

            log("SHA digest updated to:\t {:08x}{:08x}{:08x}{:08x}{:08x}",
                    ffi_sha1_get(0), ffi_sha1_get(1), ffi_sha1_get(2),
                    ffi_sha1_get(3), ffi_sha1_get(4))

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
        src_data = self.starlet.dma_read(self.dma_src, num_bytes)
        #hexdump_idt(src_data, 1)
        buf = ctypes.c_ubyte * num_bytes
        ptr = buf.from_buffer(src_data)
        ffi_sha1_input(ptr, num_bytes)
        self.dma_src += num_bytes

# -----------------------------------------------------------------------------

from Crypto.Cipher import AES

AES_FIFO_TIMEOUT = 10
class AESInterface(object):
    """ Container for the AES engine """

    def __init__(self, parent):
        self.starlet = parent

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
            ktimer_diff = self.starlet.block_count - self.key_fifo_timer
            if (ktimer_diff >= AES_FIFO_TIMEOUT):
                self.key_fifo_open = False
                self.key_fifo_timer = 0

        # Handle the IV FIFO window
        if (self.iv_fifo_open == True):
            itimer_diff = self.starlet.block_count - self.iv_fifo_timer
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
                    self.key_fifo_timer = self.starlet.block_count
                    self.key_fifo_update(value)
                else:
                    self.key_fifo_update(value)
            elif (addr == AES_IV):
                if (self.iv_fifo_open == False):
                    self.iv_fifo_open = True
                    self.iv_fifo_idx = 0
                    self.iv_fifo_timer = self.starlet.block_count
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
        log("AES DMA read: addr={:08x}, len={:08x}", addr, size)
        data = self.starlet.dma_read(self.dma_src, size)
        #hexdump_idt(data, 1)
        return data

    def dma_write(self, addr, data):
        log("AES DMA write: addr={:08x}, len={:08x}", addr, len(data))
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
            self.starlet.halt()

        if (cmd == 0x00): pass
        elif (cmd == NAND_CMD_RESET):
            log("NAND RESET")
        elif(cmd == NAND_CMD_READ0b):
            nand_data = self.nand_read(datasize)
            if (datasize <= 0x800):
                self.dma_write(self.dma_data_addr, nand_data)
            elif (datasize == 0x840):
                blk_data = nand_data[0x000:0x800]
                ecc_data = nand_data[0x800:0x840]
                self.dma_write(self.dma_data_addr, blk_data)
                self.dma_write(self.dma_ecc_addr, ecc_data)
                if ((flags & NAND_FLAG_ECC) != 0):
                    for i in range(0, 4):
                        data = nand_data[i * 512:(i * 512)+512]
                        daddr = (self.dma_ecc_addr ^ 0x40) + i * 4
                        ecc = self.calc_ecc(data)
                        self.starlet.write32(daddr, ecc)
            else:
                log("NAND unimpl datasize")
                self.starlet.halt()
        else:
            log("NAND: Unhandled cmd {:02x} ({:08x})", cmd, ctrl)
            self.starlet.halt()

    def dma_write(self, addr, data):
        self.starlet.dma_write(addr, data)
        log("NAND DMA write: addr={:08x}, len={:08x}", addr, len(data))
        #hexdump_idt(self.starlet.dma_read(addr, 0x100), 1)

    def nand_read(self, size):
        """ Return bytes from the underlying NAND device """
        off = self.addr1 * NAND_PAGE_LEN
        return self.data[off:off + size]

    def parity(self, x):
        y = 0
        while (x != 0):
            y ^= (x & 1)
            x >>= 1
        return y

    def calc_ecc(self, data):
        ecc = [ 0, 0, 0, 0 ]

        a = []
        for i in range(0, 12): a.append([0, 0])

        for i in range(0, 512):
            for j in range(0, 9):
                a[3+j][(i>>j)&1] ^= data[i]

        x = a[3][0] ^ a[3][1]
        a[0][0] = x & 0x55
        a[0][1] = x & 0xaa
        a[1][0] = x & 0x33
        a[1][1] = x & 0xcc
        a[2][0] = x & 0x0f
        a[2][1] = x & 0xf0

        for j in range(0, 12):
            a[j][0] = self.parity(a[j][0])
            a[j][1] = self.parity(a[j][1])

        a0 = 0
        a1 = 0
        for j in range(0, 12):
            a0 |= (a[j][0] << j) & 0xffffffff
            a1 |= (a[j][1] << j) & 0xffffffff

        ecc[0] = a0 & 0xff;
        ecc[1] = (a0 >> 8) & 0xff
        ecc[2] = a1 & 0xff
        ecc[3] = (a1 >> 8) & 0xff

        return (ecc[0] << 24 | ecc[1] << 16 | ecc[2] << 8 | ecc[3])

