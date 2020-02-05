from struct import pack, unpack
from sys import argv
from enum import Enum

class syscall_name(Enum):
    """ Syscall names; incomplete and occasionally wrong """
    thread_create               = 0x00
    thread_join                 = 0x01
    thread_cancel               = 0x02
    thread_get_id               = 0x03
    thread_get_pid              = 0x04
    thread_continue             = 0x05
    thread_suspend              = 0x06
    thread_yield                = 0x07
    thread_get_prio             = 0x08
    thread_set_prio             = 0x09

    mqueue_create               = 0x0a
    mqueue_destroy              = 0x0b
    mqueue_send                 = 0x0c
    mqueue_jam                  = 0x0d
    mqueue_recv                 = 0x0e

    mqueue_register_handler     = 0x0f
    mqueue_destroy_handler      = 0x10

    timer_create                = 0x11
    timer_restart               = 0x12
    timer_stop                  = 0x13
    timer_destroy               = 0x14
    timer_now                   = 0x15

    heap_create                 = 0x16
    heap_destroy                = 0x17
    heap_alloc                  = 0x18
    heap_alloc_aligned          = 0x19
    heap_free                   = 0x1a
    register_device             = 0x1b

    open                        = 0x1c
    close                       = 0x1d
    read                        = 0x1e
    write                       = 0x1f
    seek                        = 0x20
    ioctl                       = 0x21
    ioctlv                      = 0x22

    open_async                  = 0x23
    close_async                 = 0x24
    read_async                  = 0x25
    write_async                 = 0x26
    seek_async                  = 0x27
    ioctl_async                 = 0x28
    ioctlv_async                = 0x29
    resource_reply              = 0x2a

    set_uid                     = 0x2b
    get_uid                     = 0x2c
    set_gid                     = 0x2d
    get_gid                     = 0x2e

    ahb_memflush                = 0x2f
    cc_ahb_memflush             = 0x30

    swirq31                     = 0x31
    swirq18                     = 0x32
    swirq7or8                   = 0x33
    swirq                       = 0x34

    iobuf_pool_access           = 0x35
    iobuf_alloc                 = 0x36
    iobuf_free                  = 0x37
    iobuf_log_header_info       = 0x38
    iobuf_log_buffer_info       = 0x39
    iobuf_extend                = 0x3a
    iobuf_push                  = 0x3b
    iobuf_pull                  = 0x3c
    iobuf_verify                = 0x3d

    syscall_3e                  = 0x3e

    sync_before_read            = 0x3f
    sync_after_write            = 0x40

    ppc_boot                    = 0x41
    ios_boot                    = 0x42
    boot_new_ios_kernel         = 0x43

    di_reset_assert             = 0x44
    di_reset_deassert           = 0x45
    di_reset_check              = 0x46

    syscall_47                  = 0x47
    syscall_48                  = 0x48
    get_boot_vector             = 0x49
    get_hlwd_rev                = 0x4a

    debug_printf                = 0x4b
    kernel_set_ver              = 0x4c
    kernel_get_ver              = 0x4d

    di_set_spinup               = 0x4e

    virt_to_phys                = 0x4f

    dvdvideo_set                = 0x50
    dvdvideo_get                = 0x51
    exictrl_bit4_toggle         = 0x52
    exictrl_bit4_get            = 0x53

    set_ahbprot                 = 0x54
    get_busclock                = 0x55
    poke_gpio                   = 0x56
    write_ddr_reg               = 0x57
    do_poke_dbg_port            = 0x58

    load_ppc                    = 0x59
    load_module                 = 0x5a

    iosc_create_obj             = 0x5b
    iosc_delete_obj             = 0x5c
    iosc_import_secret          = 0x5d
    iosc_export_secret          = 0x5e
    iosc_import_pubkey          = 0x5f
    iosc_export_pubkey          = 0x60
    iosc_compute_sharedkey      = 0x61
    iosc_setdata                = 0x62
    iosc_getdata                = 0x63
    iosc_get_keysize            = 0x64
    iosc_get_sigsize            = 0x65
    iosc_genhash_async          = 0x66
    iosc_genhash                = 0x67
    iosc_encrypt_async          = 0x68
    iosc_encrypt                = 0x69
    iosc_decrypt_async          = 0x6a
    iosc_decrypt                = 0x6b
    iosc_verify_pubkey          = 0x6c
    iosc_gen_blockmac           = 0x6d
    iosc_gen_blockmac_async     = 0x6e
    iosc_import_cert            = 0x6f
    iosc_get_device_cert        = 0x70
    iosc_set_owner              = 0x71
    iosc_get_owner              = 0x72
    iosc_gen_rand               = 0x73
    iosc_gen_key                = 0x74
    iosc_gen_pubkey             = 0x75
    iosc_gen_cert               = 0x76
    iosc_check_dihash           = 0x77
    iosc_set_unk                = 0x78
    iosc_get_unk                = 0x79
    syscall_7a                  = 0x7a

# The maximum number of defined syscalls
SYSCALL_NR_MAX  = 0x7a

# This is the base of the syscall opcodes
INSTR_BASE      = 0xe6000010

# Offset of syscall table base in the ELF (IOSv58)
OFFSET_BASE     = 0x00028360

# -----------------------------------------------------------------------------

def get_syscall_table(filename):
    """ Read a kernel ELF, returning an array of syscall entries """
    with open(filename, "rb") as f: 
        data = f.read()

    syscalls = []
    for idx in range(0, SYSCALL_NR_MAX):
        instr       = (INSTR_BASE + (idx << 5))
        imm24       = instr & 0x00ffffff
        file_off    = (OFFSET_BASE + (idx * 4))
        impl_addr   = unpack(">L",data[file_off:file_off+4])[0] & ~1
        e = {
                'idx': idx, 
                'imm24': imm24, 
                'instr': instr, 
                'file_off': file_off, 
                'impl_addr': impl_addr 
        }
        syscalls.append(e)
    return syscalls

