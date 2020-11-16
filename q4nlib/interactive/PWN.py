# -*- coding:utf-8 -*-
from pwn import *
from q4nlib.misc import log

def config_template():
    ''''''
    config = {
    'REMOTE' : 0,
    'cmd' : '[/path/to/ld] /path/to/program [args]',
    'binary' : '/path/to/bin',
    'lib' : '/path/to/lib1 /path/to/lib2',
    'libs' : '/directory/to/libs',
    'target' : 'host port',
    'aslr' : 1
    }
    return config

class PWN:
    """
    from q4n import *
    config = {
        'REMOTE' : 1,
        'cmd' : '[/path/to/ld] /path/to/program [args]',
        'binary' : '/path/to/bin',
        'lib' : '/path/to/lib1 /path/to/lib2',
        'libs' : '/directory/to/libs',
        'target' : 'host port',
        'aslr' : 1
    }
    r = PWN(info)
    r.ia()

Notice:
    假如加载多个函数库，那么libc将加载系统libc
    """    
    # 调试
    def debugf(self,bp="",script='', sp = 0):
        '''
        bp: breakpoint
        script:
            " define xxx
            ...
            end "
        sp:
            1: gdb.attach fail
        '''
        try:
            log.Log("libc",self.lib.address)       
        except:
            pass   
        try:
            log.Log("code",self.codebase)       
        except:
            pass  
        try:        
            log.Log("heap",self.heapbase)       
        except:
            pass
        try:
            log.Log("stack",self.stack)       
        except:
            pass
        if self.config['REMOTE'] == 1:
            if script:
                with open("/tmp/gdb_script","w") as f:
                    f.write(script)
                bp+='\n'
                bp+='source /tmp/gdb_script'
            if sp:
                # ubuntu desktop
                os.system("gnome-terminal -e \'gdb -p "+ str(self.ctx.pid)+'\'')
                pause()
            else:
                gdb.attach(self.ctx, bp)
        # pause()

    def rn(self,x):
        return self.ctx.recvn(x)
    def sd(self,x):
        self.ctx.send(x)
    def sl(self,x):
        self.ctx.sendline(x)    
    def rv(self,x=4096):
        return self.ctx.recv(x)
    def ru(self,x='',drop=True):
        return self.ctx.recvuntil(str(x),drop=drop)
    def rl(self,):
        return self.ctx.recvline()
    def ia(self,):
        self.ctx.interactive()
    def ra(self,):
        return self.ctx.recvall()
    def sla(self,x,y):
        self.ctx.sendlineafter(x,y)
    def sa(self,x,y):
        self.ctx.sendafter(x,y)
    def close(self):
        self.ctx.close()
    def getflag(self):
        self.ctx.recvrepeat(0.5)
        self.sl(b"echo getflag")
        self.ru(b"getflag\n")
        self.sl(b"cat flag && echo getflag")
        flag=self.ru(b"getflag")
        return flag

    def exportflag(self,path="./export_flags"):
        ''' path: file_path '''
        flag=self.getflag()
        with open(path,"a+") as f:
            f.write(flag+'\n')        

    def _local(self):
        if 'aslr' in self.config:
            aslr = self.config['aslr']
        else:
            aslr = True

        if len(self.environ) == 0:
            self.ctx = process(self.config['cmd'].split(),aslr = aslr)
        else:
            self.ctx = process(self.config['cmd'].split(),env=self.environ,aslr = aslr)
        if self.elf == None:
            self.elf = self.ctx.elf
        if len(self.lib)==0:
            self.lib = self.ctx.libc

    def _remote(self):
        host, port = self.config['target'].split()
        self.ctx = remote(host,port)

    def __init__(self,config):
        ''' config: dict ''' 
        self.config=config

        self.ctx = None
        self.lib = []
        self.elf = None
        self.environ = {}

        self.stack=0
        self.heapbase=0
        self.codebase=0
        context(log_level='debug',os='linux')

        if 'libs' in self.config:
            self.environ['LD_LIBRARY_PATH'] = self.config['libs']


        if 'lib' in self.config:
            self.environ['LD_PRELOAD'] = self.config['lib']
            lib_list = self.config['lib'].split()
            if len(lib_list) == 1:
                self.lib = ELF(self.config['lib'])
                context.arch = self.lib.arch
            elif len(lib_list) > 1:
                for name in lib_list:
                    self.lib.append(ELF(name))
                context.arch = self.lib[0].arch
        
        if 'binary' in self.config:
            self.elf = ELF(self.config['binary'])
            context.binary = self.config['binary']

        if 'REMOTE' in self.config:
            if self.config['REMOTE'] == 0:
                self._local()
            else:
                self._remote()
        else:
            self._local()


# context.terminal=['tmux','new-window']