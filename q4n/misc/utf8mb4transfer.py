# -*- coding: utf-8 -*-
from pwn import *
from Crypto.Util.number import *
from codecs import BOM_UTF32
def _4to6(raw4):
    t = u32(raw4)
    assert( 0x4000000<= t and t <= 0x7fffffff )
    i = 0b111111001000000010000000100000001000000010000000
    i |= ((t >> 30) & 1) << 40
    i |= ((t >> 24) & 0b111111) << 32
    i |= ((t >> 18) & 0b111111) << 24
    i |= ((t >> 12) & 0b111111) << 16
    i |= ((t >> 6) & 0b111111) << 8
    i |= ((t >> 0) & 0b111111) << 0
    return long_to_bytes(i)
def _3to5(raw):
    t = u32(raw.ljust(4,'\x00'))
    assert( 0x200000 <= t and t <= 0x3ffffff )
    i = 0b1111100010000000100000001000000010000000
    i |= ((t >> 24) & 0b11) << 32
    i |= ((t >> 18) & 0b111111) << 24
    i |= ((t >> 12) & 0b111111) << 16
    i |= ((t >> 6) & 0b111111) << 8
    i |= ((t >> 0) & 0b111111) << 0
    return long_to_bytes(i)
def _3to4(raw):
    t = u32(raw.ljust(4,'\x00'))
    assert( 0x10000 <= t and t <= 0x1fffff )
    i = 0b11110000100000001000000010000000
    i |= ((t >> 18) & 0b111) << 24
    i |= ((t >> 12) & 0b111111) << 16
    i |= ((t >> 6) & 0b111111) << 8
    i |= ((t >> 0) & 0b111111) << 0
    return long_to_bytes(i)
def _2to3(raw):
    t = u32(raw.ljust(4,'\x00'))
    assert( 0x800 <= t and t <= 0xffff )
    i = 0b111000001000000010000000
    i |= ((t >> 12) & 0b1111) << 16
    i |= ((t >> 6) & 0b111111) << 8
    i |= ((t >> 0) & 0b111111) << 0
    return long_to_bytes(i)
def _1to2(raw):
    t = u32(raw.ljust(4,'\x00'))
    # print(hex(t))
    assert( 0x80 <= t and t <= 0x7ff )
    i = 0b1100000010000000
    i |= ((t >> 6) & 0b11111) << 8
    i |= ((t >> 0) & 0b111111) << 0
    return long_to_bytes(i)
def _1to1(raw):
    t = u32(raw.ljust(4,'\x00'))
    assert( 0 <= t and t <= 0x7f )
    i = 0b00000000
    i |= ((t >> 0) & 0b1111111) << 0
    return long_to_bytes(i)
def autopack(raw4):
    assert(len(raw4)==4)
    t = u32(raw4)
    if 0 <= t and t <= 0x7f:
        return _1to1(raw4)
    elif 0x80 <= t and t <= 0x7ff:
        return _1to2(raw4)
    elif 0x800 <= t and t <= 0xffff:
        return _2to3(raw4)
    elif 0x10000 <= t and t <= 0x1fffff:
        return _3to4(raw4)
    elif 0x200000 <= t and t <= 0x3ffffff:
        return _3to5(raw4)
    elif 0x4000000<= t and t <= 0x7fffffff:
        return _4to6(raw4)
    else:
        raise Exception("range >= 0x80000000", hex(t))
def mbs2utf8(raw,pad = b'\x00'):
    result = b''
    for i in range(0,len(raw),4):
        if i+4>len(raw):
            result += autopack(raw[i:].ljust(4,pad))
            break
        result += autopack(raw[i:i+4])
    return result 

def utf82mbs(raw):
    return (raw).encode('utf-32').replace(BOM_UTF32,"")

def debug_print_mbs(raw):
    result = []
    for i in range(0,len(raw),4):
        if i+4>len(raw):
            result.append(u32(raw[i:].ljust(4,'\x00')))
            break
        result.append(u32(raw[i:i+4]))
    for i in result:
        print(hex(i))
        
if __name__ == "__main__":
    cd = '.\xf4\x01\x00z\xf3\x01\x00'
    print(repr(mbs2utf8(cd)))
    # print(repr(cd.encode('utf-32')))

    # print repr(de(u'🐮🍺'))