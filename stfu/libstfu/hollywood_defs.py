#!/usr/bin/python3
""" hollywood_defs.py

Hollywood and I/O register constants.
"""

# -----------------------------------------------------------------------------
NAND_BASE       = 0x0d010000
NAND_CTRL       = NAND_BASE + 0x00
NAND_CFG        = NAND_BASE + 0x04
NAND_ADDR0      = NAND_BASE + 0x08
NAND_ADDR1      = NAND_BASE + 0x0c
NAND_DATABUF    = NAND_BASE + 0x10
NAND_ECCBUF     = NAND_BASE + 0x14
NAND_UNK        = NAND_BASE + 0x18


# -----------------------------------------------------------------------------
AES_BASE        = 0x0d020000
AES_CTRL        = AES_BASE + 0x00
AES_SRC         = AES_BASE + 0x04
AES_DST         = AES_BASE + 0x08
AES_KEY         = AES_BASE + 0x0c
AES_IV          = AES_BASE + 0x10


# -----------------------------------------------------------------------------
SHA_BASE        = 0x0d030000
SHA_CTRL        = SHA_BASE + 0x00
SHA_SRC         = SHA_BASE + 0x04
SHA_H0          = SHA_BASE + 0x08
SHA_H1          = SHA_BASE + 0x0c
SHA_H2          = SHA_BASE + 0x10
SHA_H3          = SHA_BASE + 0x14
SHA_H4          = SHA_BASE + 0x18


# -----------------------------------------------------------------------------
HW_BASE         = 0x0d800000
HW_TIMER        = HW_BASE + 0x010

HW_MEMIRR       = HW_BASE + 0x060
HW_AHBPROT      = HW_BASE + 0x064


GPIO_OUT        = HW_BASE + 0x0e0

HW_SPARE0       = HW_BASE + 0x188
HW_BOOT0        = HW_BASE + 0x18c

EFUSE_ADDR      = HW_BASE + 0x1ec
EFUSE_DATA      = HW_BASE + 0x1f0

HW_VERSION      = HW_BASE + 0x214


# -----------------------------------------------------------------------------
MEM_BASE        = 0x0d8b4000

MEM_FLUSHREQ    = MEM_BASE + 0x228 
MEM_FLUSHACK    = MEM_BASE + 0x22a


