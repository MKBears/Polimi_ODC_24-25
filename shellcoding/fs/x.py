from pwn import *

# the * before the address means to gdb "address" (duh) instead of "symbol" (like the main function)
COMMANDS = """
b  main
c
"""
context.arch = "amd64"

if args.REMOTE:
    c = remote(".training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("", gdbscript = COMMANDS)
    else:
        c = process("")

c.recvuntil(b"")
c.interactive()