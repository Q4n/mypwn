from q4n import *
debug = 1
cmd, env = ENV("./chunk")
if debug:
    r = process(cmd,env=env,aslr=0) #local
else:
    r = remote('8.8.8.8',8888) #remote
ctx.libc # get ELF(libc)
ctx.binary # get ELF(binary)
r.sla("index",str(1)) #alias sendlineafter
r.dbg("b *0xdeadbeef") # log ctx ; run debugger
r.ia()