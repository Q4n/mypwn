from __future__ import absolute_import

import sys

from q4nlib.misc import log
from q4nlib.misc import utf8utils
from q4nlib.misc import q4nctx

__all__ = ['log','utf8utils','q4nctx']


def Latin1_encode(string): # str -> bytes
    if sys.version_info[0]==3:
        return bytes(string,"Latin1")
    return bytes(string)
def Latin1_decode(string): # bytes -> str
    if sys.version_info[0]==3:
        return str(string,'Latin1')
    return string

def color(content,color='purple'):
    c = {
        "black": 30,
        "red": 31,
        "green": 32,
        "yellow": 33,
        "blue": 34,
        "purple": 35,
        "cyan": 36,
        "white": 37,
    }
    return "\033[1;{}m{}\033[0m".format(c.get(color), content)


