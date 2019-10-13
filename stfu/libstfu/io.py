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
        self.otp = OTPInterface(parent)

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
            self.starlet.write32(0x0d030008, unpack(">L",self.hbuf[0x00:0x04])[0])
            self.starlet.write32(0x0d03000c, unpack(">L",self.hbuf[0x04:0x08])[0])
            self.starlet.write32(0x0d030010, unpack(">L",self.hbuf[0x08:0x0c])[0])
            self.starlet.write32(0x0d030014, unpack(">L",self.hbuf[0x0c:0x10])[0])
            self.starlet.write32(0x0d030018, unpack(">L",self.hbuf[0x10:0x14])[0])

            hstr = hexlify(self.hbuf).decode('utf-8')
            print("[*] SHA new digest is {}".format(hstr))
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


                    self.req_done = True

            elif (addr == 0x0d030004):
                print("[*] SHA set source address to {:08x}".format(value))
                self.dma_src = value

            elif (addr == 0x0d030008): 
                print("[*] SHA write {:08x} to h[0]".format(value))
                self.hbuf[0x00:0x04] = pack(">L", value)
            elif (addr == 0x0d03000c): 
                print("[*] SHA write {:08x} to h[1]".format(value))
                self.hbuf[0x04:0x08] = pack(">L", value)
            elif (addr == 0x0d030010): 
                print("[*] SHA write {:08x} to h[2]".format(value))
                self.hbuf[0x08:0x0c] = pack(">L", value)
            elif (addr == 0x0d030014): 
                print("[*] SHA write {:08x} to h[3]".format(value))
                self.hbuf[0x0c:0x10] = pack(">L", value)
            elif (addr == 0x0d030018): 
                print("[*] SHA write {:08x} to h[4]".format(value))
                self.hbuf[0x10:0x14] = pack(">L", value)

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
class OTPInterface(object):
    def __init__(self, parent):
        self.starlet = parent
        self.data = bytearray()

    def update(self):
        return

    def on_access(self, access, address, size, value):
        """ Read commands are effectively instantaneous """
        if (access == UC_MEM_WRITE):
            if (address == 0x0d8001ec):
                if ((value & 0x80000000) != 0):
                    addr = value & 0x1f
                    otp_word = unpack(">L", self.data[addr*4:(addr*4)+4])[0]
                    self.starlet.write32(0x0d8001f0, otp_word)

                    print("[*] OTP: Command for addr={:02x}, read {:08x}".format(\
                            addr, otp_word))

                    # ?
                    self.starlet.write32(0x0d8001ec, 0)

            elif (address == 0x0d8001f0):
                print("[*] OTP: Write on OTP_DATA (?) {:08x}".format(value))


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

                    if ((flags & NAND_FLAG_ECC) != 0):
                        for i in range(0, 4):
                            data = nand_bytes[i * 512:(i * 512)+512]
                            daddr = (dma_ecc_addr ^ 0x40) + i * 4
                            ecc = self.calc_ecc(data)
                            print("[*] NAND write ECC {:08x} to {:08x}".format(\
                                    ecc, daddr))
                            self.starlet.write32(daddr, ecc)

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

    def parity(self, x):
        y = 0
        while (x != 0):
            y ^= (x & 1)
            x >>= 1
        return y

    def calc_ecc(self, data):
        ecc = [ 0, 0, 0, 0 ]
        a = []
        for i in range(0, 12):
            a.append([0, 0])

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

