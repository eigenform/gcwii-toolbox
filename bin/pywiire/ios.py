#!/usr/bin/python3

from io import BytesIO
from elftools.elf.elffile import ELFFile

from struct import pack, unpack
from enum import Enum
import re

# Pattern matching for build strings in ARM binaries
bstring_pat1 = 'IOSVersion:\s+([A-Z\d_]+)\s*:\s+((?:\d{2}\/){2}\d{2})\s+((?:\d{2}:){2}\d{2})\s+(\d{2,3})M(.*?)\s+\$'

bstring_pat2 = 'IOSVersion:\s+([A-Z\d_]+)\s*:\s+(\d{4}-\d{2}-\d{2})-(\d{2}-\d{2})\s+(\d{2,3})M(.*?)\s+\$'


class IOSPID(Enum):
    """ IOS process ID """
    KERNEL  = 0x00
    ETICKET = 0x01
    FS      = 0x02
    DIP     = 0x03
    OH0     = 0x04
    OH1     = 0x05
    EHCI    = 0x06
    SDI     = 0x07
    USBETH  = 0x08
    NET     = 0x09
    WD      = 0x0a
    WL      = 0x0b
    KD      = 0x0c
    NCD     = 0x0d
    STM     = 0x0e
    PPCBOOT = 0x0f
    SSL     = 0x10
    USB     = 0x11
    P2P     = 0x12
    WFS     = 0x13

class IOSModuleType(Enum):
    """ Collection of all observed IOS module names """

    IOSP        = 0x00
    IOS         = 0x01

    ES          = 0x02

    FFSP        = 0x03
    FFS         = 0x04

    DIP         = 0x05
    DI          = 0x06

    OH0         = 0x07
    OHCI0       = 0x08

    OH1         = 0x09
    EHCI        = 0x0a
    SDI         = 0x0b
    ETH         = 0x0c
    SO          = 0x0d
    WD          = 0x0e
    WL          = 0x0f
    KD          = 0x10
    NCD         = 0x11
    STM         = 0x12
    SSL         = 0x13

    KBD         = 0x14
    USB_HID     = 0x15
    USB_HUB     = 0x16
    USB_MSC     = 0x17
    USB_SHARED  = 0x18
    USB_VEN     = 0x19
    USB         = 0x1a

    WFSI        = 0x1b
    WFSKRN      = 0x1c

def iospid_to_type(pid, dev=None):
    if (dev == None):
        if (pid == IOSPID.DIP): return IOSModuleType.DIP
        elif (pid == IOSPID.OH0): return IOSModuleType.OH0
        elif (pid == IOSPID.OH1): return IOSModuleType.OH1
        elif (pid == IOSPID.EHCI): return IOSModuleType.EHCI
        elif (pid == IOSPID.SDI): return IOSModuleType.SDI
        elif (pid == IOSPID.USBETH): return IOSModuleType.ETH
        elif (pid == IOSPID.NET): return IOSModuleType.SO
        elif (pid == IOSPID.WD): return IOSModuleType.WD
        elif (pid == IOSPID.WL): return IOSModuleType.WL
        elif (pid == IOSPID.KD): return IOSModuleType.KD
        elif (pid == IOSPID.NCD): return IOSModuleType.NCD
        elif (pid == IOSPID.STM): return IOSModuleType.STM
        elif (pid == IOSPID.SSL): return IOSModuleType.SSL
        else:
            print("[!] Couldn't map {} to IOSModuleType".format(pid))
            exit()
    else:
        print("[!] No mapping for non-retail names yet")
        exit()


# -----------------------------------------------------------------------------
# Generic helper functions for parsing IOS ARM ELF binaries

def has_build_string(data):
    """ Returns True if the given data contains an IOS build string """
    m = re.search(b'IOSVersion.+\s\$\0', data)
    p = re.search(b'\$IOSVersion.+\s\$\n\0', data)
    return None if ((m == None) and (p == None)) else True

def is_elf(data): 
    """ Returns True if given data starts with ELF magic """
    return True if (data[0:4] == b'\x7fELF') else None

def is_elfloader(data):
    """ Returns True if given data has a valid ELFLOADER header """
    hdr_len, elf_off, elf_len = unpack(">LLL", data[0x00:0x0c])
    if (hdr_len != 0x10): return None
    ebase = hdr_len + elf_off
    return True if (data[ebase:ebase+4] == b'\x7fELF') else None

def is_dol(data):
    """ Returns True if the given data looks like a DOL header """
    hdr_len = unpack(">L", data[0:4])[0]
    if (hdr_len == 0x100): 
        return True
    else:
        return None

def get_build_string(data):
    """ Pull a IOS build string out of some binary """
    m = re.search(b'IOSVersion.+\s\$\0', data)
    n = re.search(b'IOSVersion.+\s\$\n\0', data)
    if (m != None): 
        return m.group(0).decode().strip('\x00').strip('\n')
    elif (n != None):
        return n.group(0).decode().strip('\x00').strip('\n')
    else:
        return None

def get_build_info(bstring):
    """ Parse up a build string, returning a dict """
    m = re.search(bstring_pat1, bstring)
    if (m == None):
        m = re.search(bstring_pat2, bstring)

    assert (m != None)
    name = m.group(1).strip(" ")
    date = m.group(2).strip(" ")
    time = m.group(3).strip(" ")
    ram = m.group(4).strip(" ")
    branch = m.group(5).strip(" ")
    return { 'name': name, 'date': date, 'time': time, 'ram': ram, 
            'branch': branch }


# -----------------------------------------------------------------------------
# Helper functions for parsing IOS ARM binaries with pyelftools

def get_elffile(data): 
    """ Convert some bytearray to an ELFFile object """
    return ELFFile(BytesIO(data))

def get_ios_pid(elf):
    """ Given an ELFFile, return the associated IOS PID. For now we just 
    assume that there is *exactly one* PT_NOTE segment in each ELF.
    """
    pid = None
    for seg in elf.iter_segments():
        if (seg.header['p_type'] == 'PT_NOTE'):
            ndata = seg.data()
            field = unpack(">13L", ndata[:0x34])
            assert (pid == None)
            pid = field[4]
    assert (pid != None)
    return IOSPID(pid)


