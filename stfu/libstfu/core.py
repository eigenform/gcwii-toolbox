#!/usr/bin/python3

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
from unicorn.unicorn_const import *
from capstone import *

from libstfu.io import *
from libstfu.hollywood_defs import *
from libstfu.util import *

from struct import pack, unpack

class Starlet(object):
    """ Object wrapping a Starlet emulator, implemented with Unicorn.
    We do not expect this to be exceptionally performant. However, for some
    particular [mostly simple] use-cases, it's convienient to have something
    like this implemented in Python.
    """

    def __init__(self):
        self.running = False
        self.code_loaded = False
        self.codelen = None
        self.entrypt = None
        self.mmio_logging = True
        self.use_boot0 = False
        self.symbols = {}
        self.last_block_size = 0
        self.block_count = 0
        self.last_mmio_pc = 0

        # Capstone disassembler objects
        # FIXME: It's not clear how to deal with ARM/THUMB modes

        self.dis_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN)
        self.dis_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN)

        # We explicitly create a Uc.parent reference to this object here
        # in order to integrate Unicorn's hooks into this whole abstraction

        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN)
        self.mu.parent = self

        # This StarletIO() container manages the state of all I/O devices

        self.io = StarletIO(self)

        # Configure memory mappings in Unicorn

        self.__init_mmu()

        # These hooks implement MMIO and are used to mutate the state of
        # all I/O devices wrapped inside StarletIO()

        self.__init_hook()


    """ -----------------------------------------------------------------------
    Top-level functions for initializing/destroying emulator state. 
    These are called when constructing a new Starlet() object.
    """

    def __init_mmu(self):
        """ Create all relevant memory mappings """
        self.mu.mem_map(0xffff0000, 0x00002000) # Boot ROM SRAM
        self.mu.mem_map(0x0d400000, 0x00020000) # SRAM
        self.mu.mem_map(0x00000000, 0x01800000) # MEM1
        self.mu.mem_map(0x10000000, 0x04000000) # MEM2
        self.mu.mem_map(0x0d800000, 0x00000400) # Hollywood registers
        self.mu.mem_map(0x0d806000, 0x00000400) # EXI registers
        self.mu.mem_map(0x0d8b0000, 0x00008000) # Memory controller interface?
        self.mu.mem_map(0x0d010000, 0x00001000) # NAND interface
        self.mu.mem_map(0x0d020000, 0x00001000) # AES interface
        self.mu.mem_map(0x0d030000, 0x00001000) # SHA interface

    def __init_hook(self):
        """ Initialize a set of default hooks necessary for emulation """
        self.__register_mmio_device("NAND",    0x0d010000, 0x20, self.io.nand)
        self.__register_mmio_device("AES",     0x0d020000, 0x20, self.io.aes)
        self.__register_mmio_device("SHA1",    0x0d030000, 0x20, self.io.sha)
        self.__register_mmio_device("IPC",     0x0d800000, 0xc)
        self.__register_mmio_device("TIMER",   0x0d800010, 0x4)
        self.__register_mmio_device("INTR",    0x0d800030, 0x2c)
        self.__register_mmio_device("PROT",    0x0d800060, 0x1c)
        self.__register_mmio_device("PPCGPIO", 0x0d8000c0, 0x18)
        self.__register_mmio_device("ARMGPIO", 0x0d8000dc, 0x20)
        self.__register_mmio_device("AHB",     0x0d800100, 0x4c)
        self.__register_mmio_device("PLAT",    0x0d800180, 0x20)
        self.__register_mmio_device("CLK",     0x0d8001b0, 0x38)
        self.__register_mmio_device("EFUSE",   0x0d8001ec, 0x4, self.io.otp)
        self.__register_mmio_device("MISC",    0x0d8001f4, 0x2c)
        self.__register_mmio_device("FLUSH",   0x0d8b4228, 0x2)

        # Error handling hooks
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.__get_err_unmapped_func())

        # This hook handles MMIO
        self.mu.hook_add(UC_HOOK_BLOCK, self.__get_basic_block_func())

    def __get_mmio_func(self, mmio_name, io_device):
        """ Generate an MMIO-handler specific to the provided I/O device """
        def mmio_func(uc, access, addr, size, value, user_data):
            starlet = uc.parent

            # Deal with things that need to happen instantaneously on accesses
            io_device.on_access(access, addr, size, value)

            # Template logging code shared across all MMIO accesses
            if (starlet.mmio_logging == False): return True
            this_pc = uc.reg_read(UC_ARM_REG_PC)
            accinfo = "write" if access == UC_MEM_WRITE else "read"
            valinfo = "{:08x}".format(value) if access == UC_MEM_WRITE else ""
            locinfo = starlet.__get_locinfo(this_pc)
            if (starlet.last_mmio_pc != this_pc):
                log("{} {} at {:08x}\t {}", mmio_name, accinfo, addr, locinfo)
            starlet.last_mmio_pc = this_pc

        return mmio_func

    def __register_mmio_device(self, name, addr, size, io_device=None):
        """ Register an MMIO handler specific to some I/O device """
        if (io_device == None): io_device = self.io.dummy
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, 
            self.__get_mmio_func(name, io_device), begin=addr, end=addr+size)

    def __get_basic_block_func(self):
        """ Generate a Unicorn UC_HOOK_BLOCK handler """
        def basic_block_hook(uc, addr, size, user_data):
            starlet = uc.parent

            if (self.symbols):
                log("Basic block at {:08x} ({})", addr,
                        starlet.find_symbol(addr))
            else:
                log("Basic block at {:08x}", addr)

            # Potentially service any outstanding I/O work
            starlet.io.update()

            starlet.last_block_size = size
            starlet.block_count += 1
        return basic_block_hook


    """ -----------------------------------------------------------------------
    Functions for directly mutating the machine state, writing into memory, 
    controlling the flow of execution, etc.
    """

    def run(self, halt=None):
        """ Start emulation [depending on what code is loaded] """
        if (self.use_boot0):
            self.entrypt = 0xffff0000
            until = 0x00000000
        else:
            if (self.code_loaded != True):
                warn("No binary/entrypoint specified")
                warn("Try loading a binary, or attaching NAND and boot ROM")
                return None
            else:
                until = halt if (halt != None) else self.entrypt+self.codelen
        log("Starting execution at {:08x}", self.entrypt)
        try:
            self.mu.emu_start(self.entrypt, until)
            self.running = True
        except UcError as e:
            warn("ERROR: {}", e)
            self.dump_state()
            self.running = False

    def halt(self):
        """ Halt emulation """
        self.mu.emu_stop()
        warn("Halted emulation")
        self.running = False
        self.dump_state()

    def add_breakpoint(self, addr):
        """ Add a breakpoint hook at some address """
        self.mu.hook_add(UC_HOOK_CODE, self.__get_breakpoint_func(), 
                begin=addr, end=addr)

    def add_logrange(self, addr, size):
        """ Add a hook for logging on some range of code """
        self.mu.hook_add(UC_HOOK_CODE, self.__get_logrange_func(),
                begin=addr, end=(addr+size))

    def read32(self, addr): return up32(self.mu.mem_read(addr, 4))
    def read16(self, addr): return up16(self.mu.mem_read(addr, 2))
    def write32(self, addr, val): self.mu.mem_write(addr, pack(">L", val))
    def write16(self, addr, val): self.mu.mem_write(addr, pack(">H", val))
    def dma_write(self, addr, data): self.mu.mem_write(addr, bytes(data))
    def dma_read(self, addr, size): return self.mu.mem_read(addr, size)


    """ -----------------------------------------------------------------------
    Functions for attaching devices and/or importing some other kinds
    of data into the platform/emulator.
    """

    def load_boot0(self, filename):
        """ Load the boot ROM into memory """
        with open(filename, "rb") as f: data = f.read()
        self.mu.mem_write(0xffff0000, data)
        self.use_boot0 = True
    
    def load_nand(self, filename):
        """ Attach a NAND dump to the NANDInterface. This reads the entire 
        NAND dump into memory at once """
        with open(filename, "rb") as f: self.io.nand.data = f.read()
        log("Imported NAND from {} ({:08x})", filename, len(self.io.nand.data))

    def load_code(self, filename, addr, entry=None):
        """ Load some code into memory at the specified address """
        assert self.running == False
        with open(filename, "rb") as f: ARM_CODE = f.read()
        self.codelen = len(ARM_CODE)
        self.mu.mem_write(addr, ARM_CODE)
        self.entrypt = addr if (entry == None) else entry
        self.code_loaded = True

    def load_otp(self, filename):
        """ Attach an OTP memory dump from some file """
        with open(filename, "rb") as f: OTP_DATA = f.read()
        self.io.otp.data = OTP_DATA
        log("Loaded {:08x} bytes from {} to OTP", len(OTP_DATA), filename)

    def load_symbols(self, filename):
        """ Load a CSV file with symbols into memory. Expects a file with some
        lines with [at least something like]: "address","symbol_name" """

        # Don't load symbols while running
        assert self.running == False

        with open(filename, "rb") as f:
            for line in f.readlines():
                l = line.decode('utf-8').replace('"', "")
                x = l.split(',')
                addr = int(x[0], 16)
                name = x[1]
                self.symbols[addr] = name
        log("Imported {} symbols from {}", len(self.symbols), filename)


    """ -----------------------------------------------------------------------
    Functions for logging, manipulating and managing symbols, disassembly, etc.
    """

    def find_symbol(self, addr):
        """ Given some address, find the lowest, closest symbol """
        syms = [ addr for addr in self.symbols ]
        syms.sort()
        target = min(range(len(syms)), key=lambda x: abs(syms[x] - addr))
        if (syms[target] > addr):
            target = target - 1
        func_addr = syms[target]
        return self.symbols[func_addr]

    def get_symbol(self, addr):
        """ Given an address, return the matching symbol """
        if (self.symbols): return self.symbols.get(addr)
        else: return None

    def __get_locinfo(self, addr):
        """ Format string things """
        if (self.symbols):
            sym = self.find_symbol(addr)
            return "in {} ({:08x})".format(sym, addr) if sym else "@ pc={:08x}"\
                    .format(addr)
        else:
            return "@ pc={:08x}".format(addr)

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

    def __get_logrange_func(self):
        """ Generate a hook for logging on some range of code """
        def logrange_hook(uc, addr, size, user_data):
            starlet = uc.parent
            log("Hit logpoint at {}", self.__get_locinfo(addr))
        return logrange_hook

    def __get_breakpoint_func(self):
        """ Generate a breakpoint-like hook which halts emulation """
        def breakpoint_hook(uc, addr, size, user_data):
            starlet = uc.parent
            log("[*] Breakpoint at pc={:08x}", addr)

            # Disassemble directly at the breakpoint
            starlet.disas(addr, 0x20);

            starlet.halt()
        return breakpoint_hook

    def __get_err_unmapped_func(self):
        """ Generate a handler for un-mapped memory accesses """
        def hook_unmapped(uc, access, addr, size, value, user_data):
            pc = uc.reg_read(UC_ARM_REG_PC)
            acc_type = "write" if access == UC_MEM_WRITE_UNMAPPED else "read"
            warn("MMU error: pc={:08x} Unmapped {} {:08x} on {:08x}", pc, 
                    acc_type, value, addr)
            return False
        return hook_unmapped

    def dump_state(self):
        """ Quick hack for dumping some machine state """
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        lr = self.mu.reg_read(UC_ARM_REG_LR)
        sp = self.mu.reg_read(UC_ARM_REG_SP)
        r0 = self.mu.reg_read(UC_ARM_REG_R0)
        r1 = self.mu.reg_read(UC_ARM_REG_R1)
        r2 = self.mu.reg_read(UC_ARM_REG_R2)
        r3 = self.mu.reg_read(UC_ARM_REG_R3)
        r4 = self.mu.reg_read(UC_ARM_REG_R4)
        r5 = self.mu.reg_read(UC_ARM_REG_R5)
        r6 = self.mu.reg_read(UC_ARM_REG_R6)
        r7 = self.mu.reg_read(UC_ARM_REG_R7)
        r8 = self.mu.reg_read(UC_ARM_REG_R8)
        r9 = self.mu.reg_read(UC_ARM_REG_R9)

        fmt = """pc={:08x} lr={:08x} sp={:08x}\
            \nr0={:08x} r1={:08x} r2={:08x} r3={:08x} r4={:08x} r5={:08x}\
            \nr6={:08x} r7={:08x} r8={:08x} r9={:08x} """
        log(fmt, pc,lr,sp,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9)


