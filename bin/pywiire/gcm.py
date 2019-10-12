#!/usr/bin/python3
""" gcm.py - containers/wrappers for dealing with GCN/Wii disk images """

import errno 

from os import mkdir, makedirs
from os.path import exists, isdir
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
            is_dir = True if entry[0:1] == b'\x01' else None
            noff, off, size = unpack(">3L", b'\x00' + entry[0x01:0x0c])
            name = self.__get_string(noff)
            self.ents.append({'name': name, 'off': off, 'size': size, 'dir': is_dir})
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
            is_dir = e['dir']

            # If we've reached the end of a directory
            if (idx >= dir_end_idx): 
                del path[-1:]

            # If this is the start of a directory
            if (is_dir): 
                path.append(name + "/")
                dir_end_idx = size - 2

            # Build the path for this entry
            final_path = ""
            for p in path:
                final_path += p

            # If this is a directory, no need to add anything else.
            # Otherwise, if this is a file, add the actual filename
            if (is_dir):
                e['path'] = final_path
            else:
                final_path += name
                e['path'] = final_path


class PartitionHeader(object):
    """ A Wii disc image partition header (offsets to partition table[s]) """
    def __init__(self, data):
        assert len(data) == 0x20
        self.data = data
        # There are 3 other optional tables; worry later?
        self.num_ents, self.table_off = unpack(">LL", data[0x00:0x08])
        self.table_off <<= 2


class Partition(object):
    """ A partition entry """
    def __init__(self, off, typ):
        self.off = off
        self.typ = typ


class PartitionTable(object):
    """ A Wii disc image partition table. Here we expect the user to read in 
    the right number of bytes by using a PartitionHeader().num_ents 
    """
    def __init__(self, data, num_ents):
        self.data = data
        self.parts = []
        cur = 0
        for idx in range(0, num_ents):
            off, typ = unpack(">LL", data[cur:cur+0x08])
            self.parts.append(Partition(off << 2, typ))
            cur += 0x8


class DiscHeader(object):
    """ Container for a GCM header """
    def __init__(self, data):
        # This is *sufficient* but not necessary?
        assert len(data) == 0x400
        self.data = data

        self.disc_id, self.maker_id, self.disc_num, self.disc_ver = \
                unpack(">LHbb", data[0x00:0x08])

        self.title = data[0x20:0x60].decode('utf-8')

        # Handle hash verification/disc encryption bytes
        no_hash, no_enc = unpack(">bb", data[0x60:0x62])
        self.no_hash = True if no_hash == 1 else None
        self.no_enc = True if no_enc == 1 else None


class DiscImage(object):
    """ Container representing a disk image.
    Assume we're only going to want to extract a single DATA partition.
    Ignoring UPDATE/CHANNEL partitions for now is fine I think.

    Setting 'no_partitions' ignore the format of a Wii disc and simply jump to
    reading the boot block/FST/etc and preparing data.
    """

    # These are partition types; maybe Enum these later if necessary
    PART_DATA       = 0
    PART_UPDATE     = 1
    PART_CHANNEL    = 2

    def __init__(self, fd, no_partitions=None):
        self.fd = fd
        self.prepared = None
        self.have_boot_block = None

        # Read the disc header
        self.header = DiscHeader(self.fd.read(0x400))

        # If 'no_partitions' is set, totally ignore paritions typically found
        # in Wii disc and encryption; simply read/prepare the boot block, 
        # parse the FST, etc. Assume the base offset is zero.

        if (no_partitions):
                self.read_boot_blocks(0)
                self.prepare_data(0)
                return
        
        # Otherwise, we need to deal with partitions here. 
        # Read in the partition header and partition table.

        self.fd.seek(0x40000)
        self.part_header = PartitionHeader(self.fd.read(0x20))

        self.fd.seek(self.part_header.table_off)
        self.part_table = PartitionTable(
                self.fd.read(self.part_header.num_ents * 8),
                self.part_header.num_ents)

        # TODO: Deal with DATA partitions here 
        # ...


    def read_boot_blocks(self, boff):
        """ Try to read boot block data, returning None on failure """
        self.fd.seek(boff + 0x420)
        self.boot_data = self.fd.read(0x20)
        self.bi2_data = self.fd.read(0x40)

        self.main_dol_off, self.fst_off, self.fst_len, self.max_fst_len = \
                unpack(">4L", self.boot_data[:0x10])


    def prepare_data(self, boff):
        """ Actually read and parse unencrypted data """

        # FIXME: Read main.dol
        #fd.seek(main_dol_off)

        # Extract the FST from the image and mark this disc as "prepared."
        self.fd.seek(boff + self.fst_off)
        self.fst = FST(self.fd.read(self.fst_len))
        self.prepared = True
        

    def dump_files(self, dest_dir):
        """ Dump all of the files in the FST """
        if (not self.prepared):
            print("[!] Data from this image hasn't been prepared yet")
            return

        # Create the base destination directory if it doesn't exist
        if (exists(dest_dir)):
            if (not isdir(dest_dir)):
                print("[!] Dest dir {} already exists as a file".format(dest_dir))
                exit()
        else:
            makedirs(dest_dir)

        dir_end_idx = 0xffffffff
        depth = 0
        path = []

        for idx, e in enumerate(self.fst.ents):
            off = e['off']
            size = e['size']
            name = e['name']
            is_dir = e['dir']

            # Prepend the destination directory to the path
            path = dest_dir + '/' + e['path']

            # Indentation for nice logging
            if (idx >= dir_end_idx): depth = depth - 1
            if (is_dir): dir_end_idx = size - 2

            # If this is a folder entry, try to create a directory.
            # Otherwise, if this is a file, write it to disk.
            if (is_dir):
                try:
                    makedirs(path)
                except OSError as e:
                    # Fail silently if a folder already exists
                    if (e.errno == errno.EEXIST): 
                        pass
            else:
                self.fd.seek(off)
                of_data = self.fd.read(size)
                with open(path, "wb") as of:
                    of.write(of_data)

            print("[!]\t\t{:04x} {}{}".format(idx, '  ' * depth, name))

            # Indentation for nice logging
            if (is_dir): depth = depth + 1


