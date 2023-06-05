#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

context(arch = 'amd64', os = 'linux')
context.log_level = 'debug'
context.terminal='wt.exe bash -c'.split(' ')

REMOTE = False
ip = ''
port = 0
if REMOTE:
    sh = remote(ip, port)
else:
    sh = process('./pwn')
elf = ELF('./pwn')
libc = ELF('./')
