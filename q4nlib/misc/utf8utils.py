# -*- coding: utf-8 -*-
from pwn import *
import struct
from q4nlib.misc import log

# from Crypto.Util.number import *
def b(s):
    return s.encode("latin-1") # utf-8 would cause some side-effects we don't want
def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.

    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = b('')
    n = int(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffff) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != b('\000')[0]:
            break
    else:
        # only happens when n == 0
        s = b('\000')
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b('\000') + s
    return s

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
    t = u32(raw.ljust(4,b'\x00'))
    assert( 0x200000 <= t and t <= 0x3ffffff )
    i = 0b1111100010000000100000001000000010000000
    i |= ((t >> 24) & 0b11) << 32
    i |= ((t >> 18) & 0b111111) << 24
    i |= ((t >> 12) & 0b111111) << 16
    i |= ((t >> 6) & 0b111111) << 8
    i |= ((t >> 0) & 0b111111) << 0
    return long_to_bytes(i)
def _3to4(raw):
    t = u32(raw.ljust(4,b'\x00'))
    assert( 0x10000 <= t and t <= 0x1fffff )
    i = 0b11110000100000001000000010000000
    i |= ((t >> 18) & 0b111) << 24
    i |= ((t >> 12) & 0b111111) << 16
    i |= ((t >> 6) & 0b111111) << 8
    i |= ((t >> 0) & 0b111111) << 0
    return long_to_bytes(i)
def _2to3(raw):
    t = u32(raw.ljust(4,b'\x00'))
    assert( 0x800 <= t and t <= 0xffff )
    i = 0b111000001000000010000000
    i |= ((t >> 12) & 0b1111) << 16
    i |= ((t >> 6) & 0b111111) << 8
    i |= ((t >> 0) & 0b111111) << 0
    return long_to_bytes(i)
def _1to2(raw):
    t = u32(raw.ljust(4,b'\x00'))
    # print(hex(t))
    assert( 0x80 <= t and t <= 0x7ff )
    i = 0b1100000010000000
    i |= ((t >> 6) & 0b11111) << 8
    i |= ((t >> 0) & 0b111111) << 0
    return long_to_bytes(i)
def _1to1(raw):
    t = u32(raw.ljust(4,b'\x00'))
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
def packutf8(raw,pad = b'\x00'):
    """ packutf8(raw,pad = b'\x00')
    raw: muti bytes(ascii) -> bytes
    pad: ljust char

    ret: packed bytes(utf8 packed) -> bytes
    """
    result = b''
    for i in range(0,len(raw),4):
        if i+4>len(raw):
            result += autopack(raw[i:].ljust(4,pad))
            break
        result += autopack(raw[i:i+4])
    return result 

def debug_print_mbs(raw):
    ''' debug_print_mbs(raw)
    raw: bytes
    no return
    '''
    result = []
    for i in range(0,len(raw),4):
        if i+4>len(raw):
            result.append(u32(raw[i:].ljust(4,b'\x00')))
            break
        result.append(u32(raw[i:i+4]))
    for i in result:
        if i > 0x7fffffff:
            log.Log.red('[-]',i)
        else:
            log.Log.green('[+]',i)
        
if __name__ == "__main__":
    cd = b'.\xf4\x01\x00z\xf3\x01\x00'
    print(repr(mbs2utf8(cd)))
