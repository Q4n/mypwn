# -*- coding:utf-8 -*-
from pwn import *
from ..misc.Log import Log

class PWN:
    """
    :binary  binary_path
    :llibc  libc_path if u have
    :ld  ld_path if u have
    :aslr 

Usage:
    from q4n import *
    p=PWN("./elf","./libc","./ld")
    p.proc()  or p.remote("ip",port)
    p.sl()
    debugf()
    p.ia()   

Notice:
    假如加载多个函数库，那么libc将加载系统libc
    """    

    # 调试
    def debugf(self,breakpoint="",script=''):
        try:
            # log.info("libc: "+hex(self.libc.address)) 
            Log("libc",self.libc.address)       
        except:
            pass   
        try:
            # log.info("code: "+hex(self.codebase))   
            Log("code",self.codebase)       
        except:
            pass  
        try:        
            # log.info("heap: "+hex(self.heapbase))
            Log("heap",self.heapbase)       
        except:
            pass
        try:
            # log.info("stack: "+hex(self.stack))
            Log("stack",self.stack)       
        except:
            pass
        if self.REMOTE == 0:
            if script:
                with open("/tmp/gdb_script","w") as f:
                    f.write(script)
                breakpoint+='\n'
                breakpoint+='source /tmp/gdb_script'
            gdb.attach(self.r, breakpoint)
        # pause()

    # 创建连接的主要函数
    def run(self,ip=None,port=None):
        if ip and port:
            self.REMOTE=1
            self.r=remote(ip,port)
            # self.r=remote(ip,port,timeout=2)
        elif self.llibc and self.binary and self.ld:
            self.r=process([self.ld,self.binary],env={'LD_PRELOAD':self.llibc})            
        elif self.llibc and self.binary:
            self.r=process(self.binary,env={'LD_PRELOAD':self.llibc})
        elif self.llocal:
            self.r=process(self.binary,env={"LD_LIBRARY_PATH":"."})
        else:
            self.r=process(self.binary)

    # 各种操作
    def rn(self,x):
        return self.r.recvn(x)
    def sd(self,x):
        self.r.send(x)
    def sl(self,x):
        self.r.sendline(x)    
    def rv(self,x=4096):
        return self.r.recv(x)
    def ru(self,x='',drop=True):
        return self.r.recvuntil(str(x),drop=drop)
    def rl(self,):
        return self.r.recvline()
    def ia(self,):
        self.r.interactive()
    def ra(self,):
        return self.r.recvall()
    def sla(self,x,y):
        self.r.sendlineafter(x,y)
    def sa(self,x,y):
        self.r.sendafter(x,y)
    def close(self):
        self.r.close()
    def getflag(self,getshell=True):
        if getshell:
            self.r.recvrepeat(0.5)
            self.sl("echo getflag")
            self.ru("getflag\n")
            self.sl("cat flag && echo getflag")
            flag=self.ru("getflag")
            return flag
        else:
            Log.s("not implement")
    def exportflag(self,path="./export_flags"):
        flag=self.getflag()
        with open(path,"a+") as f:
            f.write(flag+'\n')        

    # 创建连接
    def proc(self,):
        self.REMOTE=0
        self.run()
        try:
            self.libc=ELF(self.llibc)
        except:
            self.libc=self.elf.libc
    def remote(self,ip,port):
        self.run(ip,port)
        try:
            self.libc=ELF(self.llibc)
        except:
            self.libc=self.elf.libc

    def __init__(self,binary,llibc=None,ld=None,aslr=True,llocal=False,timeout=None):
        self.r=None
        self.elf=None
        self.libc=None

        self.binary=binary
        self.llibc=llibc
        self.ld=ld

        self.llocal=llocal

        self.REMOTE=0
        # 用于标识是否debug

        self.stack=0
        self.heapbase=0
        self.codebase=0

        if timeout:
            context.timeout=timeout

        try:
            self.elf=ELF(self.binary)
        except:
            pass
        finally:
            context(log_level='debug',os='linux',arch=self.elf.arch,aslr=aslr)  

# context.terminal=['tmux','new-window']