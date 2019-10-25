#!/usr/bin/python3
""" libstfu/core.py
Emulator for the 'Starlet' ARM core in the Nintendo Wii.
Implemented with Unicorn (https://github.com/unicorn-engine/unicorn).
"""

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
from unicorn.unicorn_const import *
from capstone import *

from libstfu.io import *
from libstfu.hollywood_defs import *
from libstfu.util import *

import sys
from struct import pack, unpack
import ctypes
import time

class StarletDebugger(object):
    """ A debugging interface for the Starlet() container  """
    def __init__(self, starlet_inst):

        self.starlet = starlet_inst     # Parent Starlet() object
        self.blocks = {}                # A map of basic blocks
        self.breakpoints = []           # List of active breakpoints
        self.events = []                # List of active events
        self.symbols = {}               # A map of addresses to symbols

        # Capstone [disassembler] objects
        self.dis_arm    = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN)
        self.dis_thumb  = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN)

    def enable_coverage(self):
        """ Register this UC_HOOK_BLOCK in order to collect coverage data.
        This will probably make execution significantly slower.
        """
        def __cov_hook(uc, addr, size, user_data):
            starlet = uc.parent
            entry = starlet.dbg.blocks.get(addr)
            if (entry): starlet.dbg.blocks[addr]['visited'] += 1
            else: starlet.dbg.blocks[addr] = { 'size': size, 'visited': 1 }
        self.cov_hook_idx = self.starlet.mu.hook_add(UC_HOOK_BLOCK, __cov_hook)

    def add_bp(self, addr, note=''):
        """ Create a simple breakpoint that halts at an address """
        hook_func = self.__get_hook_code_bp_tmpl(note)
        hook_id = self.starlet.mu.hook_add(UC_HOOK_CODE, hook_func, 
                begin=addr, end=addr)
        self.breakpoints.append({"addr":addr, "hook_id": hook_id})

    def __get_hook_code_bp_tmpl(self, note, user_func=None):
        """ Generate a template UC_HOOK_CODE function.
        If 'user_func(starlet)' is passed, run it in the hook. 
        If 'note' is passed, it will be written to why['note'] on exit.
        """
        if (user_func == None): 
            def user_func(starlet): 
                return

        def breakpoint_hook(uc, addr, size, user_data):
            starlet = uc.parent
            user_func(starlet)
            bp_note = note
            starlet.halt("bp", bp_note)
        return breakpoint_hook

    def add_symbol(self, addr, name): self.symbols[addr] = name
    def load_symbols(self, filename):
        """ Load a CSV file with symbols into memory. 
        Expects a file with some lines with [at least something like]: 
                    "address","symbol_name" 
        """
        with open(filename, "rb") as f:
            for line in f.readlines():
                l = line.decode('utf-8').replace('"', "")
                x = l.split(',')
                addr = int(x[0], 16)
                name = x[1]
                self.symbols[addr] = name

    def find_symbol(self, addr):
        """ Given some address, find the lowest, closest symbol """
        syms = [ addr for addr in self.symbols ]
        syms.sort()
        target = min(range(len(syms)), key=lambda x: abs(syms[x] - addr))
        if (syms[target] > addr):
            target = target - 1
        func_addr = syms[target]
        return self.symbols[func_addr]

    def disas(self, addr, size):
        """ Disassemble some amount of bytes at address """
        data = self.mu.mem_read(addr, size)

        # FIXME: how to deal with ARM/THUMB
        instrs = self.dis_thumb.disasm(data, addr, count=size)

        log("Disassembly request at {:08x}", addr)
        for instr in instrs:
            ad = instr.address
            ib = hexlify(instr.bytes).decode('utf-8')
            mn = instr.mnemonic
            op = instr.op_str
            print("\t{:08x}: \t{}\t{}\t{}".format(ad, ib, mn, op))




# -----------------------------------------------------------------------------

# FIXME: make this less shitty
# These are the memory regions backing SRAM and BROM.
# In order to implement mirroring we need to pass pointers to mem_map_ptr().

_srama_buf = bytearray(b'\x00' * 0x10000)
_srama_type = ctypes.c_ubyte * 0x10000
_sramb_buf = bytearray(b'\x00' * 0x10000)
_sramb_type = ctypes.c_ubyte * 0x10000
_brom_buf = bytearray(b'\x00' * 0x20000)
_brom_type = ctypes.c_ubyte * 0x20000
_sram_a = _srama_type.from_buffer(_srama_buf)
_sram_b = _sramb_type.from_buffer(_sramb_buf)
_brom = _brom_type.from_buffer(_brom_buf)


class Starlet(object):
    """ Top-level object wrapping a Starlet emulator (with Unicorn) """

    def __init__(self):
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN)

        self.booted = False         # Have we already entered via boot vector?
        self.boot_vector = 0        # Entrypoint used to boot the system

        self.use_boot0 = False      # Should we do a full boot?
        self.code_loaded = False    # Has user code been loaded?

        self.brom_mapped = True         # Current BROM mapping state
        self.brom_mapped_next = False   # Requested change by Hollywood I/O
        self.sram_mirror = False        # Current SRAM mirror state
        self.sram_mirror_next = False   # Requested change by Hollywood I/O

        self.time_started = 0           # Walltime when emulation started
        self.uptime_limit = None        # User-defined uptime limit
        self.halt_reason = None            # Reason for execution halt

        self.mu.parent = self               # Unicorn ref to this object
        self.io = StarletIO(self)           # I/O device container
        self.dbg = StarletDebugger(self)    # Debugger state and interface

        self.__init_mmu()                   # Configure memory mappings
        self.__init_hook()                  # Initialize required hooks


    """ -----------------------------------------------------------------------
    FIXME: Probably move these into a new container.
    MMU/MMIO-relevant functions live here.
    """

    def __init_mmu(self):
        """ Create all relevant memory mappings. """
        self.mu.mem_map_ptr(0xffff0000, 0x00010000, UC_PROT_ALL, _brom)
        self.mu.mem_map_ptr(0xfffe0000, 0x00010000, UC_PROT_ALL, _sram_a)
        self.mu.mem_map_ptr(0xfff00000, 0x00010000, UC_PROT_ALL, _sram_a)
        self.mu.mem_map_ptr(0xfff10000, 0x00010000, UC_PROT_ALL, _sram_b)
        self.mu.mem_map_ptr(0x0d400000, 0x00010000, UC_PROT_ALL, _sram_a)
        self.mu.mem_map_ptr(0x0d410000, 0x00010000, UC_PROT_ALL, _sram_b)

        self.mu.mem_map(0x0d010000, 0x00001000) # NAND interface
        self.mu.mem_map(0x0d020000, 0x00001000) # AES interface
        self.mu.mem_map(0x0d030000, 0x00001000) # SHA interface
        self.mu.mem_map(0x0d040000, 0x00000400) # ECHI
        self.mu.mem_map(0x0d050000, 0x00000400) # OHCI0
        self.mu.mem_map(0x0d060000, 0x00000400) # OHCI1
        self.mu.mem_map(0x0d800000, 0x00000400) # Hollywood registers
        self.mu.mem_map(0x0d806000, 0x00000400) # EXI registers
        self.mu.mem_map(0x0d8b0000, 0x00008000) # Memory controller interface?
        self.mu.mem_map(0x00000000, 0x01800000) # MEM1
        self.mu.mem_map(0x10000000, 0x04000000) # MEM2

    def __init_hook(self):
        """ Initialize a set of default hooks necessary for emulation.
        Bin all non-device-specific MMIOs into a generic Hollywood device like
        `self.io.hlwd` or something similar.
        """
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.__get_err_unmapped_func())
        self.mu.hook_add(UC_HOOK_INTR, self.__get_intr_function())

        self.__register_mmio_device("NAND",    0x0d010000, 0x20, self.io.nand)
        self.__register_mmio_device("AES",     0x0d020000, 0x20, self.io.aes)
        self.__register_mmio_device("SHA1",    0x0d030000, 0x20, self.io.sha)
        self.__register_mmio_device("ECHI",    0x0d040000,0x100, self.io.ehci)
        self.__register_mmio_device("OHCI0",   0x0d050000,0x200, self.io.ohci0)
        self.__register_mmio_device("OHCI1",   0x0d060000,0x200, self.io.ohci1)
        self.__register_mmio_device("IPC",     0x0d800000, 0x0c, self.io.ipc)
        self.__register_mmio_device("HW",      0x0d800010, 0x1c, self.io.hlwd)
        self.__register_mmio_device("INTR",    0x0d800030, 0x2c, self.io.intc)
        self.__register_mmio_device("HW",      0x0d800060, 0x5c, self.io.hlwd)
        self.__register_mmio_device("PPCGPIO", 0x0d8000c0, 0x18, self.io.gpio)
        self.__register_mmio_device("ARMGPIO", 0x0d8000dc, 0x20, self.io.gpio)
        self.__register_mmio_device("AHB",     0x0d800100, 0x4c, self.io.ahb)
        self.__register_mmio_device("HW",      0x0d800150, 0x98, self.io.hlwd)
        self.__register_mmio_device("EFUSE",   0x0d8001ec, 0x04, self.io.otp)
        self.__register_mmio_device("HW",      0x0d8001f4, 0x2c, self.io.hlwd)
        self.__register_mmio_device("AHB",     0x0d8b4000, 0x40, self.io.ahb)
        self.__register_mmio_device("AHB",     0x0d8b4228, 0x02, self.io.ahb)


    def __get_intr_function(self):
        def intr_func(uc, intno, user_data):
            starlet = uc.parent
            starlet.halt("interrupt", intno)
        return intr_func

    def __get_err_unmapped_func(self):
        """ Generate a handler for un-mapped memory accesses """
        def hook_unmapped(uc, access, addr, size, value, user_data):
            starlet = uc.parent
            pc = starlet.get_pc()
            d = {"access": access, "addr": addr, "size": size, "value": value}
            starlet.halt("unmapped", d)
            return False
        return hook_unmapped

    def __register_mmio_device(self, name, addr, size, io_device=None):
        """ Register an MMIO handler specific to some I/O device """
        base = addr
        tail = base + size
        if (io_device == None): io_device = self.io.dummy
        idx = self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self.__get_mmio_tmpl(name, io_device), begin=base, end=tail)

    def __get_mmio_tmpl(self, mmio_name, io_device):
        """ Generate an MMIO-handler specific to the provided I/O device """
        def mmio_func(uc, access, addr, size, value, user_data):
            starlet = uc.parent
            io_device.on_access(access, addr, size, value)
        return mmio_func

    def brom_enabled_mirror_enable(self):
        """ When the BROM is mapped, enable the SRAM mirror """
        self.mu.mem_unmap(0xffff0000, 0x00010000) # brom
        self.mu.mem_unmap(0xfffe0000, 0x00010000) # sram_a
        self.mu.mem_unmap(0xfff00000, 0x00010000) # sram_a
        self.mu.mem_unmap(0x0d400000, 0x00010000) # sram_a
        self.mu.mem_unmap(0xfff10000, 0x00010000) # sram_b
        self.mu.mem_unmap(0x0d410000, 0x00010000) # sram_b

        self.mu.mem_map_ptr(0xfff00000,0x00020000,UC_PROT_ALL, _brom)
        self.mu.mem_map_ptr(0x0d400000,0x00020000,UC_PROT_ALL, _brom)
        self.mu.mem_map_ptr(0xffff0000,0x00010000,UC_PROT_ALL, _sram_a)
        self.mu.mem_map_ptr(0xfffe0000,0x00010000,UC_PROT_ALL, _brom)

    def mirror_enabled_brom_disable(self):
        """ When the SRAM mirror is enabled, unmap the BROM """
        uc.mem_unmap(0xfff00000, 0x00020000) # brom
        uc.mem_unmap(0x0d400000, 0x00020000) # brom
        uc.mem_unmap(0xffff0000, 0x00010000) # sram_a
        uc.mem_unmap(0xfffe0000, 0x00010000) # brom

        uc.mem_map_ptr(0xfff00000,0x00010000,UC_PROT_ALL, _sram_b)
        uc.mem_map_ptr(0x0d400000,0x00010000,UC_PROT_ALL, _sram_b)
        uc.mem_map_ptr(0xfff10000,0x00010000,UC_PROT_ALL, _sram_a)
        uc.mem_map_ptr(0x0d410000,0x00010000,UC_PROT_ALL, _sram_a)
        uc.mem_map_ptr(0xfffe0000,0x00010000,UC_PROT_ALL, _sram_b)
        uc.mem_map_ptr(0xffff0000,0x00010000,UC_PROT_ALL, _sram_a)

    """ -----------------------------------------------------------------------
    Functions for directly mutating the machine state, writing into memory,
    controlling the flow of execution, etc.
    """

    def boot(self, halt=None, resume=None, timeout=0, user_until=None):
        """ Start the system at the boot vector """
        if (self.use_boot0):
            self.boot_vector = 0xffff0000
            until = 0x00000000
        else:
            if (self.code_loaded != True):
                warn("No binary/entrypoint specified")
                warn("Try loading a binary, or attaching NAND and boot ROM")
                return None
            else:
                until = halt if (halt != None) else 0x00000000

        if (user_until): until = user_until
        self.booted = True
        self.time_started = time.time()
        self.__do_mainloop(self.boot_vector, until)

    def halt(self, why, note=''):
        """ Halt emulation and set starlet.halt_reason """
        self.halt_reason = { "why": why, "note": note }
        self.mu.emu_stop()

    def __do_mainloop(self, entrypt, until, timeout=0, count=0):
        """ Do the main emulation loop here.
        FIXME: Deal with THUMB entry? 
        """

        self.mu.reg_write(UC_ARM_REG_PC, entrypt)
        self.main_ctx = None
        while True:
            try:
                if (self.main_ctx): self.mu.context_restore(self.main_ctx)

                # Restore the value of the program counter before starting
                pc = self.get_pc()
                if ((self.mu.reg_read(UC_ARM_REG_CPSR) & 0x20) != 0): pc |= 1

                # Start emulation, implicitly halting after 'count' instrs
                self.mu.emu_start(pc,until,timeout=timeout,count=self.io.hcnt)

                # Reaching this line means emulation has halted in a way that
                # Unicorn doesn't interpret as an exception. Either we:
                #
                #   - Have done 'count' instrs, and need to update I/O things
                #   - Got a halt request from something (check 'halt_reason')
                #
                # All internal interfaces and hooks should set 'halt_reason' 
                # before halting emulation, so we can deal with them here.
                # If we halt here for some other reason, set 'halt_reason' so 
                # we can communicate the reason to some external user.

                self.main_ctx = self.mu.context_save()

                # FIXME: It might be possible to do this in a hook?
                # Detect an infinite branching instruction; just halt
                if (self.read32(self.get_pc()) == 0xeafffffe):
                    self.halt_reason = {'why': 'inf_loop_branch', 'note': ''}
                    break

                # Trigger halt if we run past the user-configured uptime limit
                if (self.uptime_limit):
                    if ((time.time() - self.time_started) > self.uptime_limit):
                        self.halt_reason = {'why': 'time_limit', 'note': ''}
                        break

                # Handle any pending requested halt, if it exists
                if (self.halt_reason != None): 
                    if (self.halt_reason['why'] == 'interrupt'): break
                    if (self.halt_reason['why'] == 'unimpl'): break
                    if (self.halt_reason['why'] == 'sigint'): break
                    if (self.halt_reason['why'] == 'bp'): break

                # FIXME: Perhaps deal with this somewhere else?
                # If Hollywood requested a SRAM/BROM state change, do it now
                if (self.sram_mirror != self.sram_mirror_next):
                    if (self.brom_mapped == True) and \
                            (self.sram_mirror_next == True):
                        self.brom_enabled_mirror_enable()
                if (self.brom_mapped != self.brom_mapped_next):
                    if (self.sram_mirror == True) and \
                            (self.brom_mapped_next == False):
                        self.mirror_enabled_brom_disable()

                # Finally, do an I/O step (update I/O device states)
                self.io.update()

            # If emu_start() raises an exception, break out of the loop here
            except UcError as e:
                warn("Unicorn exception: {}", e)
                self.dump_state()
                pc = self.get_pc()
                x = self.mu.mem_read(pc - 0x10, 0x20)
                warn("Halted at pc={:08x}, here's memory at pc-0x10:", pc)
                hexdump_idt(x, 1)
                self.mu.emu_stop()
                self.halt_reason = { 'why': 'exception', 'note': '' }
                break

    def read32(self, addr): return up32(self.mu.mem_read(addr, 4))
    def read16(self, addr): return up16(self.mu.mem_read(addr, 2))
    def write32(self, addr, val): self.mu.mem_write(addr, pack(">L", val))
    def write16(self, addr, val): self.mu.mem_write(addr, pack(">H", val))
    def dma_write(self, addr, data): self.mu.mem_write(addr, bytes(data))
    def dma_read(self, addr, size): return self.mu.mem_read(addr, size)

    def get_pc(self): return self.mu.reg_read(UC_ARM_REG_PC)
    def get_lr(self): return self.mu.reg_read(UC_ARM_REG_LR)
    def get_sp(self): return self.mu.reg_read(UC_ARM_REG_SP)
    def get_r0(self): return self.mu.reg_read(UC_ARM_REG_R0)
    def get_r1(self): return self.mu.reg_read(UC_ARM_REG_R1)
    def get_r2(self): return self.mu.reg_read(UC_ARM_REG_R2)
    def get_r3(self): return self.mu.reg_read(UC_ARM_REG_R3)
    def get_r4(self): return self.mu.reg_read(UC_ARM_REG_R4)
    def get_r5(self): return self.mu.reg_read(UC_ARM_REG_R5)
    def get_r6(self): return self.mu.reg_read(UC_ARM_REG_R6)
    def get_r7(self): return self.mu.reg_read(UC_ARM_REG_R7)
    def get_r8(self): return self.mu.reg_read(UC_ARM_REG_R8)
    def get_r9(self): return self.mu.reg_read(UC_ARM_REG_R9)
    def get_r10(self): return self.mu.reg_read(UC_ARM_REG_R10)
    def get_r11(self): return self.mu.reg_read(UC_ARM_REG_R11)
    def get_r12(self): return self.mu.reg_read(UC_ARM_REG_R12)

    def hexdump(self,addr,size,idt=1): 
        hexdump_idt(self.mu.mem_read(addr, size),idt)

    """ -----------------------------------------------------------------------
    Functions for attaching devices and/or importing some other kinds
    of data into the platform/emulator.
    """

    def load_boot0(self, filename):
        """ Load the boot ROM into memory """
        with open(filename, "rb") as f: data = f.read()
        self.mu.mem_write(0xffff0000, data)
        self.use_boot0 = True

    def load_nand_file(self, filename):
        """ Attach a NAND dump to the NANDInterface. 
        This reads the entire NAND dump into memory at once
        """
        with open(filename, "rb") as f: self.io.nand.data = f.read()

    def load_nand_data(self, buf, fix_all_ecc=False):
        """ Attach a NAND dump from a bytearray.
        If 'ecc_fix' is enabled, re-compute all of the ECC data on all pages.
        I think this is necessary if the user has modified data out-of-band.
        Otherwise, the ECC errors will probably get corrected by software.
        """
        self.io.nand.data = bytearray(buf)
        if (fix_all_ecc == True): 
            self.io.nand.fix_all_ecc()

    def load_code_file(self, filename, addr, entry=None):
        """ Load a with with some  code into memory """
        with open(filename, "rb") as f: ARM_CODE = f.read()
        self.mu.mem_write(addr, ARM_CODE)
        self.boot_vector = addr if (entry == None) else entry
        self.code_loaded = True

    def load_code_buf(self, buf, addr, entry=None):
        """ Load some code into memory at the specified address """
        self.mu.mem_write(addr, buf)
        self.boot_vector = addr if (entry == None) else entry
        self.code_loaded = True

    def load_otp(self, filename):
        """ Attach an OTP memory dump from some file """
        with open(filename, "rb") as f: OTP_DATA = f.read()
        self.io.otp.data = OTP_DATA
        #log("Loaded {:08x} bytes from {} to OTP", len(OTP_DATA), filename)

    def dump_state(self, silent=False):
        """ Quick hack for dumping some machine state """
        pc = self.get_pc()
        lr = self.get_lr()
        sp = self.get_sp()
        r0 = self.get_r0()
        r1 = self.get_r1()
        r2 = self.get_r2()
        r3 = self.get_r3()
        r4 = self.get_r4()
        r5 = self.get_r5()
        r6 = self.get_r6()
        r7 = self.get_r7()
        r8 = self.get_r8()
        r9 = self.get_r9()
        r10 = self.get_r10()
        r11 = self.get_r11()
        r12 = self.get_r12()
        cpsr = self.mu.reg_read(UC_ARM_REG_CPSR)
        spsr = self.mu.reg_read(UC_ARM_REG_SPSR)
        apsr = self.mu.reg_read(UC_ARM_REG_APSR)

        fmt = """\
        pc={:08x} lr={:08x} sp={:08x} CPSR={:08x} SPSR={:08x} IPSR={:08x}\
        \nr0={:08x} r1={:08x} r2={:08x} r3={:08x} r4={:08x}  r5={:08x}\
        \nr6={:08x} r7={:08x} r8={:08x} r9={:08x} r10={:08x} r11={:08x}\
        \nr12={:08x} """

        ctx = {
            'pc': pc, 'lr': lr, 'sp': sp, 'cpsr': cpsr, 'spsr': spsr,
            'apsr': apsr, 'r0': r0, 'r1': r1, 'r2': r2, 'r3': r3,
            'r4': r4, 'r5': r5, 'r6': r6, 'r7': r7, 'r8': r8,
            'r9': r9, 'r10': r10, 'r11': r11, 'r12': r12,
        }
 
        if (silent == False):
            log(fmt, pc, lr, sp, cpsr, spsr, apsr, r0, r1, r2, r3, 
                    r4, r5, r6, r7, r8, r9, r10, r11, r12)
        return ctx


