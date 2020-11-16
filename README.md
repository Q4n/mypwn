# mypwn

自己用的pwntools

暂时只在python3上测试

roputils: `https://github.com/inaz2/roputils`
can use to solve ret2dlresolve

## install

```bash
sudo pip install q4n
```

## PWN

simple lib of pwntools


## APIs

class PWN()

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
r = PWN(info)
r.sla("ver","nb")
r.debugf("b *0xdeadbeef")
r.ia()
```

function config_template(): ret a template of config file

class Log(): print log