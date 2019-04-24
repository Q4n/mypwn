# mypwn
自己用的pwntools

对于操作的简化
```
run()
run_remote()
debugf()
pack_file()
pack_file32()
```

### usage:
`mypwn.py` 可以放置于 `~/.local/lib/python2.7/site-packages/` 中
```
from mypwn import *
run("./pwn")
sd("0xdeadbeef")
ia()
```
