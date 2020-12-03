# mypwn

自己用的pwntools

env: python2/python3

gef + gdb-mutiarch
https://github.com/Q4n/PwnEnv/tree/master/gdb-with-py3

## install

```bash
pip install q4n --user
```

or you can find the latest version in `dist` directory

## examples

see `examples/*`

## PWN

simple lib of pwntools

## APIs

### class 

#### ENV()

init local pwn environment

#### Log() 

print log

### function 

#### packutf8

ascii to utf8

then you can use fgetws to write to memory

#### debug_print_mbs

print debug log message in `packutf8`

## others

maybe compatible with `mywinpwn` :D

