#!/usr/bin/python3

from struct import pack, unpack
from Crypto.Cipher import AES
from enum import Enum

from pywiire.util import *
from pywiire.keys import *
from binascii import hexlify
import hashlib
from hexdump import hexdump

class TitleID(Enum):
    BOOT2           = 0x00000001
    SM              = 0x00000002
    BC              = 0x00000100
    MIOS            = 0x00000101

class TitleType(Enum):
    SYSTEM          = 0x00000001
    DISC            = 0x00010000
    VC              = 0x00010001
    SYSTEM_CHANNEL  = 0x00010002
    GAME_CHANNEL    = 0x00010004
    DLC             = 0x00010005
    HIDDEN_CHANNEL  = 0x00010008

class Ticket(object):
    """ Container for an eticket """
    def __init__(self, data):
        assert len(data) == 0x2a4
        self.data = data

        sigtype = unpack(">L", data[0x00:0x04])[0]
        self.common_key_idx = unpack(">b", data[0x1f1:0x1f2])[0]
        self.issuer = data[0x120:0x160].strip(b'\x00').decode('utf8')

        # Use the issuer to select the correct common key for unwrapping
        if ("XS00000003" in self.issuer):
            if (self.common_key_idx == 0):
                common_key = read_key("wii-common-key")
            elif (self.common_key_idx == 1):
                common_key = read_key("korean-common-key")
            else:
                print("[!] Unknown common key index {} for issuer {}".format(
                    self.common_key_idx, self.issuer))
                exit()
        elif ("XS00000006" in self.issuer):
            common_key = read_key("rvt-common-key")
        else:
            print("[!] Unknown issuer {} for ticket".format(self.issuer))
            exit()

        self.title_iv = b'\x00' * 0x10
        self.enc_title_key = data[0x1bf:0x1cf]
        self.iv = bytearray(data[0x1dc:0x1e4] + b'\x00' * 0x8)

        # Unwrap the key in this ticket using the provided common key
        keywrap_cipher = AES.new(common_key, AES.MODE_CBC, self.iv)
        self.title_key = keywrap_cipher.decrypt(self.enc_title_key)

        # Users can use this as a handle to decrypt some data.
        self.cipher = AES.new(self.title_key, AES.MODE_CBC, iv=self.title_iv)

class TMD(object):
    """ Container for title metadata (TMD) """
    def __init__(self, data):
        assert len(data) >= 0x1e4
        self.data = data
        self.content = []

        sigtype = unpack(">L", self.data[0x00:0x04])[0]
        self.title_id, self.title_type = unpack(">QL", self.data[0x18c:0x198])
        self.title_version, self.num_contents = unpack(">HH", self.data[0x1dc:0x1e0])

        # Iterate over each content entry in the TMD
        for i in range(0, self.num_contents): 
            cbase = 0x1e4 + (i * 0x24)
            centry = self.data[cbase:cbase + 0x24]
            iv = bytearray(centry[0x04:0x06] + b'\x00' * 0xe)
            digest = centry[0x10:]
            cid, idx, ctype, size = unpack(">LHHQ", centry[:0x10])
            if ((size % 0x40) != 0): aligned_size = (size & ~0x3f) + 0x40
            else: aligned_size = size
            assert (idx == i)
            self.content.append({'iv': iv, 'cid': cid, 'size': size, 
                'aligned_size': aligned_size, 'digest': digest})

class WAD(object):
    def __init__(self, data):
        self.data = data

        # Read the WAD header
        hlen, wtype, clen, res, ticklen, tmdlen, dlen, flen = \
                unpack(">LLLLLLLL", self.data[0x00:0x20])
        assert (hlen == 0x20)

        # Compute aligned layout of all sections
        if ((hlen % 0x40) != 0): hlen = (hlen & ~0x3f) + 0x40
        if ((clen % 0x40) != 0): clen = (clen & ~0x3f) + 0x40
        if ((ticklen % 0x40) != 0): ticklen = (ticklen & ~0x3f) + 0x40
        if ((tmdlen % 0x40) != 0): tmdlen = (tmdlen & ~0x3f) + 0x40
        if ((dlen % 0x40) != 0): dlen = (dlen & ~0x3f) + 0x40
        coff = hlen
        tickoff = coff + clen
        tmdoff = tickoff + ticklen
        doff = tmdoff + tmdlen

        # Parse ticket data
        ticket = self.data[tickoff:tickoff + ticklen]
        self.ticket = Ticket(ticket[:0x2a4])

        # Create a view of the TMD data
        self.tmd = TMD(self.data[tmdoff:tmdoff+tmdlen])
        self.content_data = []

        # Read all content entries
        cur = doff
        for entry in self.tmd.content:
            rdata = self.data[cur:cur+entry['aligned_size']]
            dig = hashlib.sha1()
            self.ticket.cipher = AES.new(self.ticket.title_key, AES.MODE_CBC, 
                    iv=entry['iv'])
            ddata = self.ticket.cipher.decrypt(rdata)
            dig.update(ddata[:entry['size']])
            assert (dig.digest() == entry['digest'])
            self.content_data.append(ddata)
            cur += entry['aligned_size']
