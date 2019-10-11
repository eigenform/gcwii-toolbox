#!/usr/bin/python3

from os.path import expanduser, exists
from struct import pack, unpack

# The global keyring path; default to ~/.wii. 
# We expect this directory to be populated with the user's personal keys.
KEYRING_PATH = expanduser("~/.wii")

def set_keyring_path(path):
    """ Set the user's keyring path """
    if (not exists(path)):
        print("[!] Keyring directory {} does not exist?!")
        exit()
    else:
        KEYRING_PATH = path

def read_key(key_name):
    """ Given some file in the keyring directory, return key material.
    This can be relative path (i.e. to keys in subdirectories).
    """
    keypath = KEYRING_PATH + "/" + keyname
    if (not exists(keypath)):
        print("[!] Key file {} does not exist?")
        exit()
    try:
        with open(path, "rb") as f:
            key = f.read()
    except:
        print("[!] Couldn't read key file {}".format(path))
        exit()
    return key

def get_otp(path=KEYRING_PATH):
    """ Fetch an OTP object from an underlying otp.bin.
    By default, expects an otp.bin in the keyring path.
    """
    path = KEYRING_PATH + "/" + "otp.bin"
    if (not exists(path)):
        print("[!] OTP file {} doesn't exist?!".format(path))
        exit()
    try:
        with open(path, "rb") as f:
            return OTP(f.read())
    except:
        print("[!] Couldn't create OTP() object from {}".format(path))
        exit()


class OTP(object):
    """ Container for Wii OTP/EFUSE storage """
    def __init__(self, data):
        assert len(data) == 0x80
        self.boot1_hash     = data[0x00:0x14]
        self.common_key     = data[0x14:0x24]
        self.ng_id          = data[0x24:0x28]
        self.ng_priv_key    = data[0x28:0x46] 
        self.nand_hmac      = data[0x44:0x58]
        self.nand_key       = data[0x58:0x68]
        self.rng_key        = data[0x68:0x78]
        self.unk_78         = data[0x78:0x7c]
        self.unk_7c         = data[0x7c:0x80]

