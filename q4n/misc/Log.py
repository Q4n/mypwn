# -*- coding:utf-8 -*-

class Log:
    """docstring for Log
    just log for num

    """
    def __init__(self, s,addr):
        self.red(s,addr)

    @staticmethod
    def red(s,addr):
        print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))
    @staticmethod
    def green(s,addr):
        print('\033[1;32;40m%20s-->0x%x\033[0m'%(s,addr))
    @staticmethod
    def yellow(s,addr):
        print('\033[1;33;40m%20s-->0x%x\033[0m'%(s,addr)) 
    @staticmethod
    def blue(s,addr):
        print('\033[1;34;40m%20s-->0x%x\033[0m'%(s,addr))