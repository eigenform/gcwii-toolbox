#!/usr/bin/python3
""" gcm.py - containers/wrappers for dealing with GCN/Wii disk images """

from enum import Enum

from os import mkdir, makedirs
from os.path import exists
from hexdump import hexdump
from struct import pack, unpack

class FST(object):
    """ 
    Simple container representing an FST. 
    The order 'self.ents' must be the same as walking the underlying data.
    For directories, the 'size' field encodes the index of the next file
    (at the same depth).
    """
    def __init__(self, data):
        self.data = data
        self.ents = []

        # Parse the FST header, get the offset of the string table
        self.num_ents = (unpack(">L", data[0x08:0x0c])[0]) - 2
        self.string_base = 0x18 + (self.num_ents * 0x0c)

        # Iterate over all FST entries and collect them in a list
        cur = 0x18
        for idx in range(0, self.num_ents):
            entry = data[cur:cur+0x0c]
            isdir = True if entry[0:1] == b'\x01' else None
            noff, off, size = unpack(">3L", b'\x00' + entry[0x01:0x0c])
            name = self.__get_string(noff)
            self.ents.append({'name': name, 'off': off, 'size': size, 'dir': isdir})
            cur += 0x0c

        # Must have self.ents populated before building paths
        self.__build_paths()


    def __get_string(self, stroff):
        """ Get a string from the FST string table """
        slen = 0
        while True:
            string_head = self.string_base + stroff
            string_tail = self.string_base + stroff + slen
            b = self.data[string_head:string_tail]
            if (len(b) > 1):
                if (b[-1] == 0): break
            slen += 1
        res = self.data[string_head:string_tail - 1]
        res = res.decode('utf-8')
        return res

    def __build_paths(self):
        """ 
        Build UNIX-like paths for all entries in the FST.
        Expect that destination directories on the host are prepended later.
        """
        path = []
        dir_end_idx = 0xffffffff

        # For each entry in the list
        for idx, e in enumerate(self.ents):
            name = e['name']
            size = e['size']
            isdir = e['dir']

            # If we've reached the end of a directory
            if (idx >= dir_end_idx): 
                del path[-1:]

            # If this is the start of a directory
            if (isdir): 
                path.append(name + "/")
                dir_end_idx = size - 2

            # Build the path for this entry
            final_path = ""
            for p in path:
                final_path += p

            # If this is a directory, no need to add anything else.
            # Otherwise, if this is a file, add the actual filename
            if (isdir):
                e['path'] = final_path
            else:
                final_path += name
                e['path'] = final_path



class GCM(object):
    """ 
    Container representing a GCM disk image.
    """
    def __init__(self, fd):
        # Read the boot data block and BI2 data block
        fd.seek(0x420)
        self.boot_data = fd.read(0x20)
        self.bi2_data = fd.read(0x40)

        # Get some important fields in boot.bin
        self.main_dol_off, self.fst_off, self.fst_len, self.max_fst_len = \
                unpack(">4L", self.boot_data[:0x10])

        # FIXME: Read main.dol
        #fd.seek(main_dol_off)

        # Extract the FST from the image
        fd.seek(self.fst_off)
        self.fst = FST(fd.read(self.fst_len))
        

    def dump_files(self, dest_dir):
        """ Dump all of the files in the FST.  """

        # Create the base destination directory if it doesn't exist
        if (not exists(dest_dir)):
            makedirs(dest_dir)

        dir_end_idx = 0xffffffff
        depth = 0
        path = []

        for idx, e in enumerate(self.ents):
            off = e['off']
            size = e['size']
            name = e['name']
            isdir = e['dir']

            # Prepend the destination directory to the path
            path = dest_dir + '/' + e['path']

            # Indentation for nice logging
            if (idx >= dir_end_idx): depth = depth - 1
            if (isdir): dir_end_idx = size - 2

            # Make a directory, otherwise write a file
            if (isdir):
                makedirs(path)
            else:
                fd.seek(off)
                of_data = fd.read(size)
                with open(path, "wb") as of:
                    of.write(of_data)

            print("[!]\t\t{:04x} {}{}".format(idx, '  ' * depth, name))

            # Indentation for nice logging
            if (isdir): depth = depth + 1


