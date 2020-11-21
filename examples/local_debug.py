#!/usr/bin/python3
from q4n import *
config = {
    'REMOTE' : 0, 
    'cmd' : './bf'
}
r = PWN(config)
r.debugf("bo 0x1000")

r.ia()