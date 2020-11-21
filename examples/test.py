#!/usr/bin/python3
from q4n import *
config = {
    'REMOTE' : 0, 
    'cmd' : './bf',
    'binary': 'bf',
    'target': '127.0.0.1 9999'

}
r = PWN(config)
r.debugf("bo 0x1000")

r.ia()