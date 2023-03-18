#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -monitor /dev/null \
    -append "console=ttyS0 oops=panic panic=1 kaslr quiet" \
    -cpu kvm64,+smep \
    -smp cores=2,threads=1 \
    -nographic \
    -s
