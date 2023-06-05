#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import base64

context(arch = 'amd64', os = 'linux')
context.log_level = 'debug'
context.terminal='wt.exe bash -c'.split(' ')

sh = remote('42.193.19.96', 9999)

sh.recvuntil(b'b\'')
part1 = sh.recvuntil(b'\'\n', drop=True)

sh.recvuntil(b'b\'')
part2 = sh.recvuntil(b'\'\n', drop=True)
print(part2)
with open('logA', 'wb') as f:
    f.write(base64.b64decode(part1))
with open('logB', 'wb') as f:
    f.write(base64.b64decode(part2))
sh.interactive()