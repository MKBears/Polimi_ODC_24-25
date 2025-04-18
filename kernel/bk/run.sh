make

./pack_initramfs.sh

qemu-system-x86_64 \
    -m 64M \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -cpu kvm64 \
    -smp 1 \
    -append "console=ttyS0 oops=panic panic=1 pti=off nokaslr quiet" \
    -monitor /dev/null \
    -serial stdio \
    -nographic \
    -s 