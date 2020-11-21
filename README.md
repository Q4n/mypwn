# mypwn

自己用的pwntools

env: python3

gef + gdb-mutiarch
https://github.com/Q4n/PwnEnv/tree/master/gdb-with-py3

## install

```bash
sudo pip install q4n
```

## PWN

simple lib of pwntools


## APIs

### class 

#### PWN()

```python
#!/usr/bin/python3
from q4n import *
config = {
    'REMOTE' : 1, # remote?
    'cmd' : '[/path/to/ld] /path/to/program [args]', # process parm
    'binary' : '/path/to/bin', # ELF() parm
    'lib' : '/path/to/lib1 /path/to/lib2', # ELF() parm, set LD_PRELOAD
    'libs' : '/directory/to/libs', # ELF() parm, set LD_LIBRARY_PATH
    'target' : 'host port', # remote target
    'aslr' : 1 # aslr on/off
}
r = PWN(config)
r.sla("ver","nb")
r.debugf("b *0xdeadbeef")
r.ia()
```

#### Log() 

print log


### function 

#### config_template(): 

ret a template of config file

