#!/usr/bin/python3

from struct import pack, unpack
from Crypto.Cipher import AES

class Ticket(object):
    """ Container for an eticket """
    def __init__(self, data, common_key):
        assert len(data) == 0x2a4
        self.data = data

        # FIXME: Potentially handle other signature types?
        sigtype = unpack(">L", data[0x00:0x04])[0]
        if (sigtype != 0x00010001):
            print("[!] Ticket has signature type {:08x}".format(sigtype))
            print("[!] Data is either not-well-formed, or this is unimplemented.")
            exit()

        # FIXME: Perhaps fanciness here to detect which common key to use?
        self.common_key_idx = unpack(">b", data[0x1f1:0x1f2])[0]

        # These are TYPICALLY the convention for unwrapping a key.
        # FIXME: May need to handle corner cases later if they arise?
        self.title_iv = b'\x00' * 0x10
        self.enc_title_key = data[0x1bf:0x1cf]
        self.iv = bytearray(data[0x1dc:0x1e4] + b'\x00' * 0x8)

        # Unwrap the key in this ticket using the provided common key
        keywrap_cipher = AES.new(common_key, AES.MODE_CBC, self.iv)
        self.title_key = keywrap_cipher.decrypt(self.enc_title_key)

        # Users can use this as a handle to decrypt some data
        self.cipher = AES.new(self.title_key, AES.MODE_CBC, iv=self.title_iv)

class TMDContent(object):
    """ Content structure (embedded in title metadata) """
    def __init__(self, data):
        assert len(data) == 0x24
        self.data = data
        self.cid,self.index,self.type,self.size = unpack(">LHHQ", data[:0x10])

class TMD(object):
    """ Container for title metadata (a TMD) """
    def __init__(self, data):
        assert len(data) >= 0x1e4
        self.data = data

        # FIXME: Potentially handle other signature types?
        sigtype = unpack(">L", data[0x00:0x04])[0]
        if (sigtype != 0x00010001):
            print("[!] Ticket has signature type {:08x}".format(sigtype))
            print("[!] Data is either not-well-formed, or this is unimplemented.")
            exit()

        self.title_id, self.title_type = unpack(">QL", data[0x18c:0x198])

        self.title_version, self.num_contents = unpack(">HH", data[0x1dc:0x1e0])

        # Get all of the content entries in this TMD
        cur = 0x1e4
        self.content = []
        for i in range(0,self.num_contents):
            self.content.append(TMDContent(data[cur:cur+0x24]))
            cur += 0x24


class WAD(object):
    def __init__(self, data):
        self.data = data

        self.header_len, self.type, self.cert_len, self.reserved, \
                self.ticket_len, self.tmd_len, self.data_len, \
                self.footer_len = unpack(">8L", data[0x00:0x20])

        assert self.header_len == 0x20

