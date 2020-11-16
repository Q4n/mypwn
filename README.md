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

```python
#!/usr/bin/python3
from q4n import *
config = {
    'REMOTE' : 1,
    'cmd' : '[/path/to/ld] /path/to/program [args]',
    'binary' : '/path/to/bin',
    'lib' : '/path/to/lib1 /path/to/lib2',
    'libs' : '/directory/to/libs',
    'target' : 'host port',
    'aslr' : 1
}
r = PWN(info)
r.sla("ver","nb")
r.debugf("b *0x1000")
r.ia()


```

config_template(): ret a template of config file
