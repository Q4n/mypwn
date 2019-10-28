# -*- coding:utf-8 -*-

from PWN import *

class BlindPWN(PWN):
    """ just connect to remote(2333 """
    def __init__(self,remote_ip,remote_port):
        self.run(remote_ip,remote_port)