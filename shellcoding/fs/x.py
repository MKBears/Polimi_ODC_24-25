from pwn import *

# the * before the address means to gdb "address" (duh) instead of "symbol" (like the main function)
COMMANDS = '''
brva 0x40146D
c
'''
context.arch = 'amd64'
exe = './forking_server'
target = '0.0.0.0'
port = 4000

if args.REMOTE:
    c = remote('forking-server.training.offensivedefensive.it', 8080, ssl=True)
else:
    if args.GDB:
        # for some reason, gdb.debug(exe, gdbscripts = COMMANDS) could not find the executable...
        # serv = process(exe)
        # serv = gdb.attach(serv, gdbscript = COMMANDS)
        serv = gdb.debug(exe, gdbscript=COMMANDS)
    else:
        serv = process(exe)

    c = remote(target, port)

c.recvuntil(b'name?\n')
c.interactive()