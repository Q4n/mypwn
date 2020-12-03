# -*- coding:utf-8 -*-
from pwn import *
from q4nlib.misc import log
from q4nlib.misc import color

from pwnlib.tubes.sock import sock
from pwnlib import gdb
from q4nlib.misc import q4nctx

tube.sd = tube.send
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.sla = tube.sendlineafter
tube.rv = tube.recv
tube.rn = tube.recvn
tube.ru = tube.recvuntil
tube.rl = tube.recvline
tube.ra = tube.recvall
tube.rr = tube.recvregex
tube.rp = tube.recvrepeat
tube.ia = tube.interactive

def try_log():
    try:
        log.Log("ctx.libc.address",q4nctx.libc.address)       
    except:
        pass   
    try:
        log.Log("ctx.binary.address",q4nctx.binary.address)       
    except:
        pass   
    try:
        log.Log("ctx.code",q4nctx.code)       
    except:
        pass  
    try:        
        log.Log("ctx.heap",q4nctx.heap)       
    except:
        pass
    try:
        log.Log("ctx.stack",q4nctx.stack)       
    except:
        pass

def sock_dbg(self,script = '', sp = 0):
    try_log()
def process_dbg(self, script = '', sp = 0):
    try_log()
    if sp == 0:
        gdb.attach(self, script)
    else:
        with open("/tmp/gdb_script","w") as f:
            f.write(script)
        os.system("gnome-terminal -e \'gdb -p "+ str(self.pid)+" --command=/tmp/gdb_script"+'\'')
        pause()

sock.dbg = sock_dbg
process.dbg = process_dbg

def ENV(cmdline = '' , libpath = '', ldpath = '',log_level='debug'):
    ''' ENV(cmdline = '' , libpath = '', ldpath = '',log_level='debug'):  init local pwn environ
    cmdline: your process 
    libpath: .so path or directory
    ldpath: ld.so path

    return: (packed_cmdline:list, env: dict)
    
    example:
        # context.terminal=['tmux','new-window']
        cmd,environ = ENV('/bin/sh')
        r = process(cmd,env=environ)
    '''
    # default use arch amd64
    context(log_level=log_level,os='linux',arch = "amd64")
    env = dict()

    cmdlist = list()
    if cmdline:
        cmdlist = cmdline.split()
        if '.sh' not in cmdlist[0]:
            q4nctx.binary = ELF(cmdlist[0])
            context.binary = cmdlist[0]

    if libpath:
        if os.path.isdir(libpath):
            env['LD_LIBRARY_PATH'] = libpath
        elif os.path.isfile(libpath):
            env['LD_PRELOAD'] = libpath
            q4nctx.libc = ELF(libpath)
            context.arch = q4nctx.libc.arch
        else:
            raise Exception(color("err `libpath` in ENV",'red'))
    elif q4nctx.binary:
        q4nctx.libc = q4nctx.binary.libc

    if ldpath:
        if os.path.isfile(libpath):
            cmdlist.insert(0,ldpath)
        else:
            raise Exception(color("err `ldpath` in ENV",'red'))
    
    return (cmdlist, env)
