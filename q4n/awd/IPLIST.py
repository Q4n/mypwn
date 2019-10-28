# -*- coding:utf-8 -*-

from pwn import *
class IPLIST:
    # IPLIST('125-127-100.100-110.110-120.20-25').result --> List

    def __init__(self,ip):
        self.result=[]
        def iplist(ip_range):
            # ip_range: '125-127.100-110.110-120.20-25'
            tmp=ip_range.split('.')
            tmp_list=[]
            result=[]
            for i in tmp:
                if '-' in i:
                    tmp1=i.split('-')
                    if len(tmp1) == 2:
                        tmp_list.append((int(tmp1[0]),int(tmp1[1]),1))
                    elif len(tmp1)==3:
                        tmp_list.append((int(tmp1[0]),int(tmp1[1]),int(tmp1[2])))
                    else:
                        print("[-] Error ip_range!")
                        exit()
                else:
                    tmp_list.append((int(i),int(i)+1,1))
            for a in range(tmp_list[0][0],tmp_list[0][1],tmp_list[0][2]):
                for b in range(tmp_list[1][0],tmp_list[1][1],tmp_list[1][2]):
                    for c in range(tmp_list[2][0],tmp_list[2][1],tmp_list[2][2]):
                        for d in range(tmp_list[3][0],tmp_list[3][1],tmp_list[3][2]):
                            tmpip=".".join([str(a),str(b),str(c),str(d)])
                            result.append(tmpip)
            return result
        self.result=iplist(ip)