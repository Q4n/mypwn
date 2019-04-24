# -*- coding:utf-8 -*-
from pwn import *

def run(binary='',aslr=1,DEBUG=1):
    if DEBUG:
        context.log_level = 'debug'
    global libc,elf,r
    if binary!='':
        elf = ELF(binary, checksec = 0)
        r = process(binary, aslr=aslr)
        libc=elf.libc

def run_remote(ip='',port=0,DEBUG=0):
    if DEBUG:
        context.log_level = 'debug'
    global r
    r = remote(ip, port)

sd = lambda x : r.send(x)
sl = lambda x : r.sendline(x)
rv = lambda x = 2048 : r.recv(x)
ru = lambda x : r.recvuntil(x)
rl = lambda : r.recvline()
ia = lambda : r.interactive()
ra = lambda : r.recvall()
sla = lambda x,y: r.sendlineafter(x,y)
sa = lambda x,y : r.sendafter(x,y)

def debugf(context):
    gdb.attach(r,context)

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


